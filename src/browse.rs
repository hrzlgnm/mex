// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use simple_dns::{
    rdata::RData, Packet, PacketFlag, Question, ResourceRecord, CLASS, QCLASS, QTYPE, TYPE,
};

use socket2::{Domain, SockAddr};
use socket_pktinfo::PktInfoUdpSocket;

mod iface;
mod listener;
mod send;
mod wire;
pub use iface::available_interfaces;
pub use iface::link_stats;
pub use iface::local_ips;
pub use iface::validate_selection;
pub use iface::LinkStats;
use iface::*;
use listener::*;
pub(crate) use send::inferred_question_packet;
use send::*;
pub(crate) use wire::is_local_name;
pub(crate) use wire::is_proto_label;
pub(crate) use wire::is_sub_label;
pub(crate) use wire::nsec_address_types;
pub(crate) use wire::parse_packet;
pub use wire::question_fields;
pub use wire::record_fields;
pub use wire::record_type_from_u16;
pub(crate) use wire::rtype_from_str;
pub(crate) use wire::rtype_label;
pub(crate) use wire::rtype_name;
pub(crate) use wire::strip_local_suffix;
pub(crate) use wire::wire_rdata_len;
#[cfg(test)]
use wire::*;

const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const MDNS_PORT: u16 = 5353;

/// DNS-SD service type enumeration name (RFC 6763 §9), without the
/// trailing root dot.
pub(crate) const ENUM_SERVICE: &str = "_services._dns-sd._udp.local";
/// How often the listener re-enumerates interfaces: picks up
/// bridges and other links that appear at runtime, drops dead ones from
/// the transmit set, and re-joins flapped ones (replug or down/up with
/// the same name would otherwise stay deaf: the kernel join does not
/// survive the interface going away).
const IFACE_REFRESH: Duration = Duration::from_secs(10);

/// Address family of a listener socket: selects the interface list,
/// the join call, and the per-packet transmit interface.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Family {
    V4,
    V6,
}

impl Family {
    fn label(self) -> &'static str {
        match self {
            Family::V4 => "v4",
            Family::V6 => "v6",
        }
    }
}

impl QuerySocket for PktInfoUdpSocket {
    fn pin(&self, egress: Egress) -> std::io::Result<()> {
        match egress {
            Egress::V4(ip) => self.set_multicast_if_v4(&ip),
            Egress::V6(idx) => self.set_multicast_if_v6(idx),
        }
    }

    fn send_to(&self, bytes: &[u8], dest: SocketAddr) -> std::io::Result<()> {
        PktInfoUdpSocket::send_to(self, bytes, &SockAddr::from(dest)).map(|_| ())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordSection {
    Answer,
    Authority,
    Additional,
    /// Known answers in query packets (RFC 6762 §7.1): beliefs, not facts.
    KnownAnswer,
    /// Question rows reuse RawRecord; section is not meaningful there.
    Question,
}

impl RecordSection {
    /// Stable lowercase label for dumps and messages.
    pub fn as_str(self) -> &'static str {
        match self {
            RecordSection::Answer => "answer",
            RecordSection::Authority => "authority",
            RecordSection::Additional => "additional",
            RecordSection::KnownAnswer => "known-answer",
            RecordSection::Question => "question",
        }
    }
}

#[derive(Debug, Clone)]
pub struct RawRecord {
    pub name: String,
    /// Original owner-name labels, retained so DNS-SD subtype identifiers
    /// can be handled as wire octets rather than lossy display text.
    pub owner_labels: Vec<Vec<u8>>,
    /// Original PTR target labels, retained for subtype validation in
    /// service enumeration records.
    pub ptr_target_labels: Option<Vec<Vec<u8>>>,
    pub rtype: u16,
    pub rtype_str: String,
    pub flush_bit: bool,
    pub qu: bool,
    /// Whether any DNS name on this row (owner, question, or name-valued
    /// rdata) contained non-UTF-8 bytes. mDNS names MUST be precomposed
    /// UTF-8 (RFC 6762 §16); the display strings are lossy, so this is
    /// detected at parse time on raw label bytes and surfaced by the
    /// analyzer instead of failing silently on refresh.
    pub invalid_utf8: bool,
    pub ttl: u32,
    pub rdata: String,
    /// Standalone wire encoding of this record, captured at parse time so
    /// the hex view doesn't depend on the shared packet buffer.
    pub wire: Vec<u8>,
    pub source: SocketAddr,
    /// Name of the interface the packet arrived on (e.g. `"br0"`), from
    /// IP_PKTINFO. Empty when unknown; used only for display/diagnosis.
    pub iface: String,
    /// Kernel interface index the packet arrived on (0 when the kernel
    /// supplied none). Survives when `iface` is empty so unmapped
    /// traffic stays identifiable (`if#7`) instead of one opaque pile.
    pub ifindex: u32,
    /// Whether the packet's destination was the mDNS multicast group.
    /// False means the packet was unicast to us; that holds for queries
    /// (question and known-answer rows) as well as responses. Since the
    /// sockets listen on 5353, a unicast response is a QU reply, never a
    /// legacy unicast one (RFC 6762 §6.7). The analyzer only uses it to
    /// name unicast replies in finding messages, never for severity.
    pub dst_is_multicast: bool,
    /// Which DNS section carried the record. Responses merge answer /
    /// authority / additional sections; known answers ride in queries.
    pub section: RecordSection,
    pub received_at: Instant,
    /// The question this response most likely answered, stamped at ingest
    /// for out-of-scope records (`anomalies::is_mdns_answer_type` false)
    /// only; `None` elsewhere or when no matching question was seen
    /// shortly before.
    pub trigger: Option<QueryTrigger>,
}

impl RawRecord {
    /// The responder address, suffixed with the ingress interface when
    /// pktinfo provided one, so multi-link traffic can be told apart.
    /// The `%iface` zone notation is only valid for IPv6 link-local
    /// unicast (RFC 4007); everything else uses `@iface`. A link-local
    /// source that already carries a zone (scope id) is shown as-is
    /// instead of gaining a second suffix. Shared by the Records table
    /// and findings that stand in for rows.
    pub fn source_label(&self) -> String {
        if self.iface.is_empty() {
            return self.source.to_string();
        }
        match self.source {
            SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() && v6.scope_id() == 0 => {
                format!("{}%{}", self.source, self.iface)
            }
            SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() => self.source.to_string(),
            _ => format!("{}@{}", self.source, self.iface),
        }
    }
}

/// The question a response most likely answered: the latest question for
/// the record's owner name, of any type, seen shortly before the response
/// arrived. mDNS responses carry no question section (RFC 6762 §6), so
/// this is a timing heuristic, good enough to tell responses to our own
/// queries from responses to someone else's.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct QueryTrigger {
    /// `name TYPE`, e.g. `fritz.box. A`.
    pub question: String,
    /// Whether this mex instance sent it (vs. a remote querier).
    pub own: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecordField {
    pub label: String,
    pub start: usize,
    pub end: usize,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub answers: Vec<RawRecord>,
    pub questions: Vec<RawRecord>,
    /// Known answers carried in query packets (RFC 6762 §7.1). Never filed
    /// as sightings (queries are beliefs, not facts); used only for
    /// duplicate question suppression (§7.3) subset checks.
    pub query_kas: Vec<RawRecord>,
    /// DNS header response code for a response packet; queries are `None`.
    pub rcode: Option<u8>,
    pub received_at: Instant,
    pub raw_bytes: Vec<u8>,
    pub source: SocketAddr,
}

#[derive(Debug, Clone)]
pub struct KnownAnswer {
    pub target: String,
    pub ttl: u32,
    /// Interface the answer was observed on; empty when unknown, in which
    /// case it is sent everywhere.
    pub iface: String,
}

#[derive(Debug, Clone)]
pub struct QueryRequest {
    pub name: String,
    pub record_type: TYPE,
    /// PTR target names to include as known answers (owner name = self.name).
    /// Each TTL must be the *remaining* TTL, and callers must omit targets
    /// with less than half of the original TTL left (RFC 6762 §7.1).
    pub known_answers: Vec<KnownAnswer>,
    /// mDNS unicast-response (QU) bit. Only set on the first query of the
    /// startup batch (RFC 6762 §5.4); retransmissions and later questions
    /// are QM.
    pub qu: bool,
}

/// Query sender for the listener thread. Each request is queued once
/// and the poll loop is woken, so it leaves immediately on every usable
/// link of both families (solicited queries reach v6-only responders
/// too).
pub struct QueryTx {
    tx: mpsc::Sender<QueryRequest>,
    waker: Arc<mio::Waker>,
    transmit: Arc<TransmitState>,
}

/// Whether each family can transmit right now: its socket is open and
/// it has at least one usable link. The single source of truth: the
/// listener writes it through `update` on every interface refresh
/// (the first one runs in `spawn`, before the app's first tick), and
/// the app only reads it. Starts from socket availability, so starting
/// with no usable link reports one pause. Both families live in one
/// atomic, written and read in one step, so a v4-to-v6 handoff in one
/// refresh never shows "no family" in between.
#[derive(Debug)]
pub struct TransmitState {
    /// `V4_BIT` | `V6_BIT` for the families that can transmit.
    bits: AtomicU8,
    /// Tests pin the flags so the real listener can't overwrite them.
    pinned: AtomicBool,
}

const V4_BIT: u8 = 0b01;
const V6_BIT: u8 = 0b10;

fn family_bit(family: Family) -> u8 {
    match family {
        Family::V4 => V4_BIT,
        Family::V6 => V6_BIT,
    }
}

fn transmit_bits(v4: bool, v6: bool) -> u8 {
    (if v4 { V4_BIT } else { 0 }) | (if v6 { V6_BIT } else { 0 })
}

impl TransmitState {
    pub fn new(v4: bool, v6: bool) -> Self {
        Self {
            bits: AtomicU8::new(transmit_bits(v4, v6)),
            pinned: AtomicBool::new(false),
        }
    }

    /// Per-family flags as (v4, v6), from one load.
    pub fn flags(&self) -> (bool, bool) {
        let bits = self.bits.load(Ordering::Relaxed);
        (bits & V4_BIT != 0, bits & V6_BIT != 0)
    }

    /// Whether any family can transmit.
    pub fn any(&self) -> bool {
        self.bits.load(Ordering::Relaxed) != 0
    }

    /// Pin both flags for a test: later listener updates are ignored,
    /// so the result doesn't depend on the host's interfaces.
    #[cfg(test)]
    pub fn pin(&self, v4: bool, v6: bool) {
        self.pinned.store(true, Ordering::Relaxed);
        self.bits.store(transmit_bits(v4, v6), Ordering::Relaxed);
    }

    /// Record, after a refresh, whether each family has usable links
    /// (`None`: its socket never opened, keep it as is), stored in one
    /// step. Returns the transition to log once per family, in
    /// (v4, v6) order; pausing and resuming are never logged per
    /// skipped query.
    fn update(&self, v4: Option<bool>, v6: Option<bool>) -> [Option<PauseLog>; 2] {
        if self.pinned.load(Ordering::Relaxed) {
            return [None, None];
        }
        let old = self.bits.load(Ordering::Relaxed);
        let mut new = old;
        for (family, has_links) in [(Family::V4, v4), (Family::V6, v6)] {
            match has_links {
                Some(true) => new |= family_bit(family),
                Some(false) => new &= !family_bit(family),
                None => {}
            }
        }
        // The listener is the only writer: one store publishes both.
        self.bits.store(new, Ordering::Relaxed);
        [Family::V4, Family::V6].map(|family| {
            let bit = family_bit(family);
            match (old & bit != 0, new & bit != 0) {
                (true, false) => Some(PauseLog::Paused),
                (false, true) => Some(PauseLog::Resumed),
                _ => None,
            }
        })
    }
}

impl QueryTx {
    /// The shared per-family transmit state.
    pub fn transmit(&self) -> &TransmitState {
        &self.transmit
    }

    /// Queue a query and wake the listener. Returns `true` when the
    /// listener accepted the request — the transport may still fail to
    /// send (encode error, closed socket), which is logged in
    /// `send_query` and cannot be reflected here. Wakes may coalesce:
    /// the queue is the source of truth, drained on every loop pass.
    pub fn send(&self, req: QueryRequest) -> bool {
        if self.tx.send(req).is_err() {
            return false;
        }
        if let Err(e) = self.waker.wake() {
            log::warn!("mex: cannot wake listener: {e}");
        }
        true
    }
}

/// Refused-packet accounting shared with the App thread: RFC 6762 §11
/// off-link discards plus messages the DNS codec cannot decode at all.
/// The listener only bumps these; rendering reads them.
#[derive(Debug, Default)]
pub struct DropStats {
    count: AtomicU64,
    last: Mutex<Option<(SocketAddr, Instant)>>,
    malformed: AtomicU64,
    malformed_last: Mutex<Option<(SocketAddr, Instant)>>,
}

impl DropStats {
    pub fn note(&self, source: SocketAddr) {
        self.count.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = self.last.lock() {
            *last = Some((source, Instant::now()));
        }
    }

    pub fn total(&self) -> u64 {
        self.count.load(Ordering::Relaxed)
    }

    pub fn last(&self) -> Option<(SocketAddr, Instant)> {
        self.last.lock().ok().and_then(|last| *last)
    }

    /// A datagram that failed message-level decode: no event, no records,
    /// nothing for the browser to file. Counted so a garbage storm is
    /// distinguishable from a quiet network.
    pub fn note_malformed(&self, source: SocketAddr) {
        self.malformed.fetch_add(1, Ordering::Relaxed);
        if let Ok(mut last) = self.malformed_last.lock() {
            *last = Some((source, Instant::now()));
        }
    }

    pub fn malformed_total(&self) -> u64 {
        self.malformed.load(Ordering::Relaxed)
    }

    pub fn malformed_last(&self) -> Option<(SocketAddr, Instant)> {
        self.malformed_last.lock().ok().and_then(|last| *last)
    }
}

pub fn spawn(
    selection: Option<HashSet<String>>,
) -> Result<(QueryTx, mpsc::Receiver<Event>, Arc<DropStats>)> {
    let (tx, rx) = mpsc::channel();
    let (query_tx, query_rx) = mpsc::channel();
    let drops = Arc::new(DropStats::default());
    let poll = mio::Poll::new()?;
    let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN)?);
    // Each family opens on its own: one failing (e.g. IPv6 disabled)
    // leaves the other running, logged once.
    let v4 = FamilySocket::open(Family::V4, poll.registry());
    let v6 = FamilySocket::open(Family::V6, poll.registry());
    require_transport(v4.is_some(), v6.is_some())?;
    let transmit = Arc::new(TransmitState::new(v4.is_some(), v6.is_some()));
    let shared = SharedWithApp {
        drops: drops.clone(),
        transmit: transmit.clone(),
    };
    let mut listener = Listener::new(poll, v4, v6, tx, query_rx, shared, selection);
    // First interface refresh before returning: the transmit flags then
    // reflect usable links by the app's first tick, so no startup query
    // is counted as sent while nothing can transmit.
    listener.refresh();
    listener.next_refresh = Instant::now() + IFACE_REFRESH;
    thread::spawn(move || listener.run());
    Ok((
        QueryTx {
            tx: query_tx,
            waker,
            transmit,
        },
        rx,
        drops,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dns_sd_label_helpers() {
        assert!(is_proto_label(b"_tcp"));
        assert!(is_proto_label(b"_UDP"));
        assert!(!is_proto_label(b"_sctp"));
        assert!(!is_proto_label(b"tcp"));
        assert!(is_sub_label(b"_Sub"));
        assert!(!is_sub_label(b"sub"));
    }

    #[test]
    fn local_suffix_helpers() {
        assert_eq!(strip_local_suffix("printer.local."), Some("printer"));
        assert_eq!(strip_local_suffix("Printer.LOCAL"), Some("Printer"));
        assert_eq!(strip_local_suffix("_http._tcp.local"), Some("_http._tcp"));
        assert_eq!(strip_local_suffix("local."), None);
        assert_eq!(strip_local_suffix(".local"), None);
        assert_eq!(strip_local_suffix("localhost"), None);
        assert_eq!(strip_local_suffix("example.com"), None);
        // Multi-byte text right before the suffix must not panic.
        assert_eq!(strip_local_suffix("ä.local"), Some("ä"));
        assert_eq!(strip_local_suffix("éélocal"), None);
        assert!(is_local_name("LOCAL."));
        assert!(is_local_name("host.local"));
        assert!(!is_local_name("host.example"));
        assert!(!is_local_name("notlocal"));
        assert!(is_local_name(".local"));
    }

    #[test]
    fn nsec_bitmap_ignores_words_of_the_next_name() {
        // Instance names keep spaces; a word like "A" in the name is not a
        // bitmap type.
        assert_eq!(
            nsec_address_types("My A Printer._http._tcp.local. AAAA"),
            (vec![28], false)
        );
        assert_eq!(
            nsec_address_types("host.local. A AAAA"),
            (vec![1, 28], false)
        );
        assert_eq!(
            nsec_address_types("Odd. A Name.local. TXT SRV"),
            (vec![], true)
        );
        assert_eq!(nsec_address_types("host.local."), (vec![], false));
        // Empty bitmap with a dotted name holding a mnemonic word.
        assert_eq!(
            nsec_address_types("Odd. A Name._http._tcp.local."),
            (vec![], false)
        );
    }

    #[test]
    fn rtype_names_round_trip() {
        for &(code, name) in RTYPE_NAMES {
            assert_eq!(rtype_label(code), name);
            assert_eq!(rtype_from_str(name), Some(code));
        }
        assert_eq!(rtype_label(99), "TYPE99");
        // Only in-scope types are named: SOA and MX are numbers only.
        assert_eq!(rtype_label(6), "TYPE6");
        assert_eq!(rtype_label(15), "TYPE15");
        assert_eq!(rtype_label(13), "HINFO");
        assert_eq!(rtype_from_str("SOA"), None);
        assert_eq!(rtype_from_str("TYPE6"), Some(6));
        for &(code, _) in RTYPE_NAMES {
            assert!(
                crate::anomalies::is_mdns_answer_type(code)
                    || crate::anomalies::is_mdns_question_type(code),
                "type {code} is named but out of scope"
            );
        }
        assert_eq!(rtype_from_str("TYPE47"), Some(47));
        assert_eq!(rtype_from_str("TYPE99"), Some(99));
        assert_eq!(rtype_from_str("bogus"), None);
    }

    #[test]
    fn v6_dest_carries_interface_scope() {
        match mdns_dest_v6(7) {
            SocketAddr::V6(v6) => assert_eq!(v6.scope_id(), 7),
            _ => panic!("expected v6 mDNS dest"),
        }
    }

    fn known_answer<'a>(owner: &'a str, target: &'a str, ttl: u32) -> ResourceRecord<'a> {
        ResourceRecord::new(
            simple_dns::Name::new_unchecked(owner),
            CLASS::IN,
            ttl,
            RData::PTR(simple_dns::Name::new_unchecked(target).into()),
        )
    }

    fn test_source() -> std::net::SocketAddr {
        "192.168.178.60:5353".parse().unwrap()
    }

    fn roundtrip_query(req: &QueryRequest) -> Event {
        let bytes = encode_query(req, "").expect("query must encode");
        parse_packet(&bytes, test_source(), std::net::IpAddr::V4(MDNS_V4), "", 0).unwrap()
    }

    #[test]
    fn known_answers_are_scoped_to_egress_interface() {
        use super::KnownAnswer;
        let kas = vec![
            KnownAnswer {
                target: "a.".into(),
                ttl: 100,
                iface: "br0".into(),
            },
            KnownAnswer {
                target: "b.".into(),
                ttl: 100,
                iface: "".into(),
            },
        ];
        let got = known_answers_for_iface(&kas, "br0");
        assert_eq!(got, vec![("a.", 100), ("b.", 100)]);
        let got = known_answers_for_iface(&kas, "enx");
        assert_eq!(got, vec![("b.", 100)]);
        // Unknown egress link: keep everything rather than go silent.
        let got = known_answers_for_iface(&kas, "");
        assert_eq!(got, vec![("a.", 100), ("b.", 100)]);
    }

    #[test]
    fn query_known_answers_are_not_filed_as_records() {
        let mut q = Packet::new_query(0);
        q.questions.push(simple_dns::Question::new(
            simple_dns::Name::new_unchecked("svc._http._tcp.local."),
            QTYPE::TYPE(TYPE::PTR),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        q.answers.push(known_answer(
            "svc._http._tcp.local.",
            "Inst.svc._http._tcp.local.",
            120,
        ));
        let ev = parse_packet(
            &q.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "enx",
            2,
        )
        .unwrap();
        // The known answer must not become a sighting; the question stays.
        assert!(ev.answers.is_empty());
        assert_eq!(ev.questions.len(), 1);
        assert_eq!(ev.questions[0].name, "svc._http._tcp.local.");
        assert!(!ev.questions[0].qu);
        // ... but the KA is retained for §7.3 duplicate suppression.
        assert_eq!(ev.query_kas.len(), 1);
        assert_eq!(ev.query_kas[0].rdata, "Inst.svc._http._tcp.local.");
        assert_eq!(ev.query_kas[0].iface, "enx");

        let mut r = Packet::new_reply(0);
        r.answers.push(known_answer(
            "svc._http._tcp.local.",
            "Inst.svc._http._tcp.local.",
            120,
        ));
        let ev = parse_packet(
            &r.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "enx",
            2,
        )
        .unwrap();
        assert_eq!(ev.answers.len(), 1);
        assert_eq!(ev.answers[0].rdata, "Inst.svc._http._tcp.local.");
        assert_eq!(ev.answers[0].iface, "enx");
        assert!(ev.questions.is_empty());
        assert!(ev.query_kas.is_empty());
    }

    #[test]
    fn query_qu_bit_is_parsed() {
        let mut q = Packet::new_query(0);
        q.questions.push(simple_dns::Question::new(
            simple_dns::Name::new_unchecked("svc._http._tcp.local."),
            QTYPE::TYPE(TYPE::PTR),
            QCLASS::CLASS(CLASS::IN),
            true,
        ));
        let ev = parse_packet(
            &q.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "enx",
            2,
        )
        .unwrap();
        assert_eq!(ev.questions.len(), 1);
        assert!(ev.questions[0].qu);
    }

    fn flush_response(flush: bool) -> Event {
        let mut msg = Packet::new_reply(0);
        msg.answers.push(
            ResourceRecord::new(
                simple_dns::Name::new_unchecked("test.local."),
                CLASS::IN,
                120,
                RData::A(simple_dns::rdata::A {
                    address: u32::from(Ipv4Addr::new(192, 168, 1, 10)),
                }),
            )
            .with_cache_flush(flush),
        );
        parse_packet(
            &msg.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "",
            7,
        )
        .unwrap()
    }

    #[test]
    fn response_flush_bit_survives_parse() {
        // simple-dns exposes the top CLASS bit natively as
        // `cache_flush` (RFC 6762 §10.2).
        assert!(flush_response(true).answers[0].flush_bit);
        assert!(!flush_response(false).answers[0].flush_bit);
    }

    #[test]
    fn packet_index_survives_parse_without_name() {
        // flush_response parses with ("", 7): no name, index kept.
        let ev = flush_response(false);
        assert_eq!(ev.answers.len(), 1);
        assert!(ev.answers[0].iface.is_empty());
        assert_eq!(ev.answers[0].ifindex, 7);
    }

    #[test]
    fn query_ka_flush_bit_survives_parse() {
        let mut q = Packet::new_query(0);
        q.questions.push(simple_dns::Question::new(
            simple_dns::Name::new_unchecked("test.local."),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        q.answers.push(
            ResourceRecord::new(
                simple_dns::Name::new_unchecked("test.local."),
                CLASS::IN,
                120,
                RData::A(simple_dns::rdata::A {
                    address: u32::from(Ipv4Addr::new(192, 168, 1, 10)),
                }),
            )
            .with_cache_flush(true),
        );
        let ev = parse_packet(
            &q.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "",
            7,
        )
        .unwrap();
        assert!(ev.answers.is_empty());
        assert_eq!(ev.query_kas.len(), 1);
        assert!(ev.query_kas[0].flush_bit);
    }

    #[test]
    fn unusable_interfaces_are_skipped() {
        fn iface(status: if_addrs::IfOperStatus, p2p: bool) -> if_addrs::Interface {
            if_addrs::Interface {
                name: "eth0".into(),
                addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                    ip: Ipv4Addr::new(192, 168, 1, 2),
                    netmask: Ipv4Addr::new(255, 255, 255, 0),
                    prefixlen: 24,
                    broadcast: None,
                }),
                index: Some(2),
                oper_status: status,
                is_p2p: p2p,
            }
        }
        use if_addrs::IfOperStatus as St;
        assert!(usable_interface(&iface(St::Up, false)));
        assert!(!usable_interface(&iface(St::Down, false)));
        assert!(!usable_interface(&iface(St::LowerLayerDown, false)));
        assert!(!usable_interface(&iface(St::Unknown, false)));
        assert!(!usable_interface(&iface(St::Dormant, false)));
        assert!(!usable_interface(&iface(St::Testing, false)));
        assert!(!usable_interface(&iface(St::NotPresent, false)));
        assert!(!usable_interface(&iface(St::Up, true)));
        assert!(!usable_interface(&iface(St::Unknown, true)));
    }

    #[test]
    fn instance_names_with_spaces_and_punctuation_reach_the_wire() {
        // Regression: the old ASCII-only name parser rejected this
        // instance name, so the SRV refresh was dropped before the
        // socket and the record expired with nothing on the wire.
        let name = "pihole [b8:27:eb:9d:87:e1]._workstation._tcp.local";
        let ev = roundtrip_query(&QueryRequest {
            name: name.to_string(),
            record_type: TYPE::SRV,
            known_answers: Vec::new(),
            qu: false,
        });
        assert_eq!(ev.questions.len(), 1);
        assert_eq!(ev.questions[0].name, format!("{name}."));
        assert_eq!(ev.questions[0].rtype, 33);
    }

    #[test]
    fn utf8_instance_names_survive_the_wire_round_trip() {
        // A name read off the wire must re-encode to the same bytes, or
        // the refresh query asks for a name the responder does not own.
        let name = "Küche._http._tcp.local";
        let ev = roundtrip_query(&QueryRequest {
            name: name.to_string(),
            record_type: TYPE::SRV,
            known_answers: Vec::new(),
            qu: false,
        });
        assert_eq!(ev.questions[0].name, format!("{name}."));
    }

    #[test]
    fn split_instance_labels_keep_instance_dots_in_one_label() {
        assert_eq!(
            split_instance_labels("amzn.dmgr:ABC._amzn-wplay._tcp.local"),
            ["amzn.dmgr:ABC", "_amzn-wplay", "_tcp", "local"]
        );
        // Subtype owners, enumeration, service types, and host names
        // split on every dot.
        assert_eq!(
            split_instance_labels("_printer._sub._http._tcp.local."),
            ["_printer", "_sub", "_http", "_tcp", "local"]
        );
        assert_eq!(
            split_instance_labels("_services._dns-sd._udp.local"),
            ["_services", "_dns-sd", "_udp", "local"]
        );
        assert_eq!(
            split_instance_labels("_http._tcp.local"),
            ["_http", "_tcp", "local"]
        );
        assert_eq!(
            split_instance_labels("FritzBoxRepeater.fritz.box"),
            ["FritzBoxRepeater", "fritz", "box"]
        );
        // Last-match wins: `._tcp.`-like text inside the instance label
        // still resolves to the real service suffix.
        assert_eq!(
            split_instance_labels("foo._tcp.bar._http._tcp.local"),
            ["foo._tcp.bar", "_http", "_tcp", "local"]
        );
    }

    #[test]
    fn record_wire_is_expanded_with_class_bits() {
        // Pins the hex-pane encoding: owner name written out in full (no
        // compression pointers), type, class with the §10.2 flush bit,
        // TTL, rdlen, rdata.
        let rec = ResourceRecord::new(
            simple_dns::Name::new_unchecked("test.local."),
            CLASS::IN,
            120,
            RData::A(simple_dns::rdata::A {
                address: u32::from(Ipv4Addr::new(192, 168, 1, 10)),
            }),
        )
        .with_cache_flush(true);
        let mut want = vec![4];
        want.extend_from_slice(b"test");
        want.push(5);
        want.extend_from_slice(b"local");
        want.push(0);
        want.extend([0x00, 0x01]); // A
        want.extend([0x80, 0x01]); // IN + flush bit
        want.extend(120u32.to_be_bytes());
        want.extend([0x00, 0x04]); // rdlen
        want.extend([192, 168, 1, 10]);
        assert_eq!(record_wire(&rec), want);

        // Self-referential names are the case compression would fire on:
        // NSEC next_name == owner must still come back expanded. Under
        // the compressed builder the second occurrence would be a
        // pointer, so this fails if the builder choice regresses.
        let nsec = ResourceRecord::new(
            simple_dns::Name::new_unchecked("host.local."),
            CLASS::IN,
            120,
            RData::NSEC(simple_dns::rdata::NSEC::from_types(
                simple_dns::Name::new_unchecked("host.local."),
                &[TYPE::A],
            )),
        );
        let mut want = vec![4];
        want.extend_from_slice(b"host");
        want.push(5);
        want.extend_from_slice(b"local");
        want.push(0);
        want.extend([0x00, 0x2F]); // NSEC
        want.extend([0x00, 0x01]); // IN, no flush
        want.extend(120u32.to_be_bytes());
        want.extend([0x00, 0x0F]); // rdlen
        want.extend([4]);
        want.extend_from_slice(b"host");
        want.push(5);
        want.extend_from_slice(b"local");
        want.push(0);
        want.extend([0x00, 0x01, 0x40]); // window 0, len 1, A bit
        assert_eq!(record_wire(&nsec), want);
    }

    #[test]
    fn known_answers_with_spaces_are_sent() {
        let ev = roundtrip_query(&QueryRequest {
            name: "_http._tcp.local".to_string(),
            record_type: TYPE::PTR,
            known_answers: vec![KnownAnswer {
                target: "Denon AVR-X1400H._http._tcp.local".to_string(),
                ttl: 4000,
                iface: String::new(),
            }],
            qu: false,
        });
        assert_eq!(ev.query_kas.len(), 1);
        assert_eq!(ev.query_kas[0].rdata, "Denon AVR-X1400H._http._tcp.local.");
    }

    #[test]
    fn oversized_ka_list_truncates_but_keeps_question() {
        // A dense network must not EMSGSIZE the refresh into silence:
        // known answers shed to the RFC 6762 §17 cap, question intact.
        let kas: Vec<KnownAnswer> = (0..2000)
            .map(|i| KnownAnswer {
                target: format!("instance-{i:05}._http._tcp.local"),
                ttl: 120,
                iface: String::new(),
            })
            .collect();
        let bytes = encode_query(
            &QueryRequest {
                name: "_http._tcp.local".to_string(),
                record_type: TYPE::PTR,
                known_answers: kas,
                qu: false,
            },
            "",
        )
        .expect("query must encode");
        assert!(bytes.len() <= MAX_QUERY_BYTES);
        let ev = parse_packet(
            &bytes,
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "br0",
            3,
        )
        .unwrap();
        assert_eq!(ev.questions.len(), 1);
        assert_eq!(ev.questions[0].name, "_http._tcp.local.");
        assert!(!ev.query_kas.is_empty());
        assert!(ev.query_kas.len() < 2000);
    }

    #[test]
    fn out_of_scope_records_keep_only_rdlength() {
        use simple_dns::rdata::{HINFO, MX, SOA};
        use simple_dns::CharacterString;
        let host = || simple_dns::Name::new_unchecked("host.local.");
        let mut msg = Packet::new_reply(0);
        msg.answers.push(ResourceRecord::new(
            host(),
            CLASS::IN,
            4500,
            RData::SOA(SOA {
                mname: host(),
                rname: simple_dns::Name::new_unchecked("admin.host.local."),
                serial: 1,
                refresh: 2,
                retry: 3,
                expire: 4,
                minimum: 5,
            }),
        ));
        msg.answers.push(ResourceRecord::new(
            host(),
            CLASS::IN,
            120,
            RData::MX(MX {
                preference: 10,
                exchange: host(),
            }),
        ));
        msg.additional_records.push(ResourceRecord::new(
            host(),
            CLASS::IN,
            120,
            RData::HINFO(HINFO {
                cpu: CharacterString::new(b"X86_64").unwrap(),
                os: CharacterString::new(b"LINUX").unwrap(),
            }),
        ));
        // Compressed on the wire: the SOA's names shrink to pointers, so
        // its RDLENGTH differs from a re-encoded (expanded) record.
        let raw = msg.build_bytes_vec_compressed().unwrap();
        let ev =
            parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3).unwrap();
        assert_eq!(ev.answers.len(), 3);
        let walked = walk_records(&raw).unwrap().1;
        let wire_lengths: Vec<u16> = walked
            .answer
            .iter()
            .chain(&walked.additional)
            .map(|w| w.rdlength)
            .collect();
        let soa = &ev.answers[0];
        assert_eq!(soa.rtype_str, "TYPE6");
        assert_eq!(soa.rdata, format!("rdlength={}", wire_lengths[0]));
        assert!(
            usize::from(wire_lengths[0]) < 2 * "host.local.".len() + 20,
            "compressed SOA must report its on-wire length, got {}",
            wire_lengths[0]
        );
        assert!(soa.wire.is_empty(), "no rdata bytes kept");
        let mx = &ev.answers[1];
        assert_eq!(mx.rtype_str, "TYPE15");
        assert_eq!(mx.rdata, format!("rdlength={}", wire_lengths[1]));
        assert!(mx.wire.is_empty());
        // HINFO is in scope: decoded, named, with its wire bytes.
        let hinfo = &ev.answers[2];
        assert_eq!(hinfo.rtype_str, "HINFO");
        assert_eq!(hinfo.section, RecordSection::Additional);
        assert!(hinfo.rdata.contains("X86_64") && hinfo.rdata.contains("LINUX"));
        assert!(!hinfo.wire.is_empty());
    }

    #[test]
    fn malformed_out_of_scope_rdata_never_drops_the_packet() {
        // Response: A host.local, SOA host.local with 3 bytes of garbage
        // rdata, and an EDNS0 OPT pseudo-record in Additional.
        let name: &[u8] = b"\x04host\x05local\x00";
        let mut raw = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 1];
        raw.extend_from_slice(name);
        raw.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1]);
        raw.extend_from_slice(name);
        raw.extend_from_slice(&[0, 6, 0, 1, 0, 0, 0, 120, 0, 3, 0xff, 0xff, 0xff]);
        raw.extend_from_slice(&[0, 0, 41, 0x05, 0xa0, 0, 0, 0, 0, 0, 0]);
        assert!(
            Packet::parse(&raw).is_err(),
            "the SOA is malformed: decoding it fails the packet"
        );
        let ev = parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3)
            .expect("packet survives its malformed out-of-scope record");
        let rows: Vec<(u16, &str)> = ev
            .answers
            .iter()
            .map(|r| (r.rtype, r.rdata.as_str()))
            .collect();
        assert_eq!(
            rows,
            vec![(1, "10.0.0.1"), (6, "rdlength=3")],
            "OPT is no row"
        );
        assert_eq!(ev.answers[1].rtype_str, "TYPE6");
        assert_eq!(ev.raw_bytes, raw, "the stored packet stays as received");
    }

    #[test]
    fn opt_before_other_additionals_keeps_records_aligned() {
        // Response: A host.local in Answer; Additional holds OPT first,
        // then AAAA host.local, then an MX. The parser lifts the OPT out
        // of Additional; walked types and lengths must still line up.
        let name: &[u8] = b"\x04host\x05local\x00";
        let mut raw = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 3];
        raw.extend_from_slice(name);
        raw.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 120, 0, 4, 10, 0, 0, 1]);
        raw.extend_from_slice(&[0, 0, 41, 0x05, 0xa0, 0, 0, 0, 0, 0, 0]);
        raw.extend_from_slice(name);
        raw.extend_from_slice(&[0, 28, 0, 1, 0, 0, 0, 120, 0, 16]);
        raw.extend_from_slice(&[0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1]);
        raw.extend_from_slice(name);
        raw.extend_from_slice(&[0, 15, 0, 1, 0, 0, 0, 120, 0, 4, 0, 10, 0xc0, 12]);
        let ev = parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3)
            .expect("packet parses");
        let rows: Vec<(u16, &str, RecordSection)> = ev
            .answers
            .iter()
            .map(|r| (r.rtype, r.rdata.as_str(), r.section))
            .collect();
        assert_eq!(
            rows,
            vec![
                (1, "10.0.0.1", RecordSection::Answer),
                (28, "fd00::1", RecordSection::Additional),
                (15, "rdlength=4", RecordSection::Additional),
            ]
        );
    }

    #[test]
    fn unwalkable_packet_is_dropped_not_parsed_raw() {
        // A valid MX followed by a record whose RDLENGTH runs past the
        // end: dropped as a whole, the MX never reaches the parser.
        let name: &[u8] = b"\x04host\x05local\x00";
        let mut raw = vec![0, 0, 0x84, 0, 0, 0, 0, 2, 0, 0, 0, 0];
        raw.extend_from_slice(name);
        raw.extend_from_slice(&[0, 15, 0, 1, 0, 0, 0, 120, 0, 4, 0, 10, 0xc0, 12]);
        raw.extend_from_slice(name);
        raw.extend_from_slice(&[0, 1, 0, 1, 0, 0, 0, 120, 0, 9, 10, 0]);
        assert!(walk_records(&raw).is_none());
        assert!(
            parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3).is_none()
        );
    }

    #[test]
    fn question_fields_survive_malformed_out_of_scope_known_answer() {
        // Query: one PTR question, one known answer that is a malformed
        // SOA. Highlighting the question must not decode (and fail on)
        // the out-of-scope known answer.
        let mut raw = vec![0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0];
        raw.extend_from_slice(b"\x05_http\x04_tcp\x05local\x00");
        raw.extend_from_slice(&[0, 12, 0, 1]);
        raw.extend_from_slice(&[0xc0, 12, 0, 6, 0, 1, 0, 0, 0, 120, 0, 3, 0xff, 0xff, 0xff]);
        assert!(
            Packet::parse(&raw).is_err(),
            "the SOA known answer is malformed"
        );
        let fields = question_fields(&raw, "_http._tcp.local", "PTR").expect("question fields");
        assert!(fields.iter().any(|f| f.label == "QTYPE"), "{fields:?}");
    }

    #[test]
    fn walk_records_skips_questions_and_rejects_truncation() {
        let mut msg = Packet::new_query(0);
        msg.questions.push(Question::new(
            simple_dns::Name::new_unchecked("host.local."),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        msg.answers.push(ResourceRecord::new(
            simple_dns::Name::new_unchecked("host.local."),
            CLASS::IN,
            120,
            RData::A(simple_dns::rdata::A {
                address: 0x0a00_0001,
            }),
        ));
        let raw = msg.build_bytes_vec().unwrap();
        let (bytes, records) = walk_records(&raw).unwrap();
        assert_eq!(
            records.answer,
            vec![WireRecord {
                rtype: 1,
                rdlength: 4
            }]
        );
        assert_eq!(bytes, raw, "in-scope records stay untouched");
        assert_eq!(walk_records(&raw[..raw.len() - 6]), None);
    }

    #[test]
    fn response_nsec_shows_resolved_name_and_iface() {
        let mut msg = Packet::new_reply(0);
        msg.answers.push(ResourceRecord::new(
            simple_dns::Name::new_unchecked("host.local."),
            CLASS::IN,
            120,
            RData::NSEC(simple_dns::rdata::NSEC::from_types(
                simple_dns::Name::new_unchecked("host.local."),
                &[TYPE::A],
            )),
        ));
        let raw = msg.build_bytes_vec().unwrap();
        let addr: SocketAddr = "192.168.178.5:5353".parse().unwrap();
        let ev = parse_packet(&raw, addr, std::net::IpAddr::V4(MDNS_V4), "br0", 3).unwrap();
        assert_eq!(ev.answers.len(), 1);
        assert_eq!(ev.answers[0].rdata, "host.local. A");
        assert_eq!(ev.answers[0].iface, "br0");
        assert!(ev.questions.is_empty());
    }

    #[test]
    fn nsec_wire_round_trip_preserves_types() {
        // Compression pointers in other records must not corrupt the
        // NSEC type bitmaps: the codec parses them natively.
        let mut msg = Packet::new_reply(0);
        msg.answers.push(ResourceRecord::new(
            simple_dns::Name::new_unchecked("host.local."),
            CLASS::IN,
            120,
            RData::NSEC(simple_dns::rdata::NSEC::from_types(
                simple_dns::Name::new_unchecked("host.local."),
                &[TYPE::A, TYPE::TXT],
            )),
        ));
        let raw = msg.build_bytes_vec().unwrap();
        let ev =
            parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3).unwrap();
        assert_eq!(ev.answers[0].rdata, "host.local. A TXT");
    }

    fn name_with_invalid_label() -> simple_dns::Name<'static> {
        // Wire bytes live outside the packet buffer: leak one label so
        // the name can be built without borrowing a test local.
        let raw: &'static [u8] = Box::leak(vec![0xff].into_boxed_slice());
        let labels: &'static [simple_dns::Label<'static>] = Box::leak(
            vec![
                simple_dns::Label::new_unchecked(raw),
                simple_dns::Label::new_unchecked(&b"local"[..]),
            ]
            .into_boxed_slice(),
        );
        simple_dns::Name::new_with_labels(labels)
    }

    #[test]
    fn non_utf8_owner_and_question_names_are_flagged() {
        let mut msg = Packet::new_reply(0);
        msg.answers.push(ResourceRecord::new(
            name_with_invalid_label(),
            CLASS::IN,
            120,
            RData::A(simple_dns::rdata::A {
                address: u32::from(Ipv4Addr::new(192, 168, 1, 10)),
            }),
        ));
        let ev = parse_packet(
            &msg.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "br0",
            3,
        )
        .unwrap();
        assert!(ev.answers[0].invalid_utf8);
        assert!(ev.answers[0].name.contains('�'));

        let mut q = Packet::new_query(0);
        q.questions.push(simple_dns::Question::new(
            name_with_invalid_label(),
            QTYPE::TYPE(TYPE::A),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        let ev = parse_packet(
            &q.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "br0",
            3,
        )
        .unwrap();
        assert!(ev.questions[0].invalid_utf8);
    }

    #[test]
    fn non_utf8_rdata_names_are_flagged_and_valid_utf8_is_clean() {
        let target = name_with_invalid_label();
        let mut msg = Packet::new_reply(0);
        msg.answers.push(ResourceRecord::new(
            simple_dns::Name::new_unchecked("svc._http._tcp.local."),
            CLASS::IN,
            120,
            RData::PTR(target.into()),
        ));
        let ev = parse_packet(
            &msg.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "br0",
            3,
        )
        .unwrap();
        assert!(ev.answers[0].invalid_utf8);

        // Precomposed UTF-8 (RFC 6762 §16) is the compliant case: no flag.
        let mut ok = Packet::new_reply(0);
        ok.answers.push(known_answer(
            "Küche._http._tcp.local.",
            "Küche._http._tcp.local.",
            120,
        ));
        let ev = parse_packet(
            &ok.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "br0",
            3,
        )
        .unwrap();
        assert!(!ev.answers[0].invalid_utf8);
        assert_eq!(ev.answers[0].name, "Küche._http._tcp.local.");
    }

    #[test]
    fn response_questions_are_ignored_per_rfc6762_s6() {
        // RFC 6762 §6: responses MUST NOT contain questions; received
        // ones are silently ignored, never filed as observed queries.
        let mut msg = Packet::new_reply(0);
        msg.questions.push(simple_dns::Question::new(
            simple_dns::Name::new_unchecked("svc._http._tcp.local."),
            QTYPE::TYPE(TYPE::PTR),
            QCLASS::CLASS(CLASS::IN),
            false,
        ));
        msg.answers.push(known_answer(
            "svc._http._tcp.local.",
            "Inst.svc._http._tcp.local.",
            120,
        ));
        let ev = parse_packet(
            &msg.build_bytes_vec().unwrap(),
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "br0",
            3,
        )
        .unwrap();
        assert!(ev.questions.is_empty());
        assert_eq!(ev.answers.len(), 1);
        assert_eq!(ev.query_kas.len(), 0);
    }

    #[test]
    fn packet_context_tags_section_and_destination() {
        use std::net::{IpAddr, Ipv4Addr};
        let mut msg = Packet::new_reply(0);
        msg.answers.push(known_answer("a.local.", "x.local.", 120));
        msg.name_servers
            .push(known_answer("b.local.", "x.local.", 120));
        msg.additional_records
            .push(known_answer("c.local.", "x.local.", 120));
        let raw = msg.build_bytes_vec().unwrap();
        let mcast = IpAddr::V4(MDNS_V4);
        let ev = parse_packet(&raw, test_source(), mcast, "br0", 3).unwrap();
        assert_eq!(
            ev.answers.iter().map(|r| r.section).collect::<Vec<_>>(),
            vec![
                RecordSection::Answer,
                RecordSection::Authority,
                RecordSection::Additional,
            ]
        );
        assert!(ev.answers.iter().all(|r| r.dst_is_multicast));
        let unicast: IpAddr = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let ev = parse_packet(&raw, test_source(), unicast, "br0", 3).unwrap();
        assert!(ev.answers.iter().all(|r| !r.dst_is_multicast));
    }

    #[test]
    fn response_code_is_kept_for_responses_not_queries() {
        let reply = Packet::new_reply(0);
        let mut raw = reply.build_bytes_vec().unwrap();
        raw[3] = (raw[3] & 0xf0) | 3;
        let response =
            parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3).unwrap();
        assert_eq!(response.rcode, Some(3));

        let query = encode_query(
            &QueryRequest {
                name: "host.local.".to_string(),
                record_type: TYPE::A,
                known_answers: Vec::new(),
                qu: false,
            },
            "br0",
        )
        .unwrap();
        let query = parse_packet(
            &query,
            test_source(),
            std::net::IpAddr::V4(MDNS_V4),
            "br0",
            3,
        )
        .unwrap();
        assert_eq!(query.rcode, None);
    }

    #[test]
    fn backfill_rescans_once_per_unknown_index() {
        use std::cell::Cell;
        use std::net::{IpAddr, Ipv4Addr};
        let scans = Cell::new(0);
        let scan = || {
            scans.set(scans.get() + 1);
            (
                HashMap::from([(7u32, "wlp13s0".to_string())]),
                HashMap::from([(
                    7u32,
                    vec![(
                        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                        IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                    )],
                )]),
            )
        };
        let mut ifnames = HashMap::new();
        let mut subnets: SubnetMap = HashMap::new();
        let mut unknown = HashSet::new();
        // Miss + scan finds it: both maps backfilled for later packets.
        backfill_link(7, &mut ifnames, &mut subnets, &mut unknown, &scan);
        assert_eq!(ifnames.get(&7).map(String::as_str), Some("wlp13s0"));
        assert!(subnets.contains_key(&7));
        assert_eq!(scans.get(), 1);
        // Remembered from here on: no second scan for the same index.
        backfill_link(7, &mut ifnames, &mut subnets, &mut unknown, &scan);
        assert_eq!(scans.get(), 1);
        // Miss + absent from scan: one scan, stays unknown.
        backfill_link(9, &mut ifnames, &mut subnets, &mut unknown, &scan);
        assert_eq!(scans.get(), 2);
        assert!(unknown.contains(&9));
        assert!(!ifnames.contains_key(&9));
        assert!(!subnets.contains_key(&9));
    }

    #[test]
    fn mdns_multicast_dest_matches_only_mdns_groups() {
        assert!(mdns_multicast_dest(&IpAddr::V4(Ipv4Addr::new(
            224, 0, 0, 251
        ))));
        assert!(mdns_multicast_dest(&MDNS_V6.into()));
        assert!(!mdns_multicast_dest(&IpAddr::V4(Ipv4Addr::new(
            224, 0, 0, 252
        ))));
        assert!(!mdns_multicast_dest(&IpAddr::V4(Ipv4Addr::new(
            192, 168, 1, 10
        ))));
    }

    #[test]
    fn source_on_link_applies_subnet_mask() {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        let subnets: SubnetMap = HashMap::from([
            (
                2u32,
                vec![(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                )],
            ),
            (
                3u32,
                vec![(
                    IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                    IpAddr::V6(Ipv6Addr::new(0xffff, 0xfc00, 0, 0, 0, 0, 0, 0)),
                )],
            ),
        ]);
        // Same /24: local.
        assert!(source_on_link(
            &subnets,
            2,
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))
        ));
        // Different subnet: off-link, refuse.
        assert!(!source_on_link(
            &subnets,
            2,
            &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
        ));
        // Same fe80::/10: local.
        assert!(source_on_link(
            &subnets,
            3,
            &IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2))
        ));
        // Global source against a link-local prefix: refuse.
        assert!(!source_on_link(
            &subnets,
            3,
            &IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
        ));
        // Unknown index and family mismatch fail closed.
        assert!(!source_on_link(
            &subnets,
            9,
            &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))
        ));
        assert!(!source_on_link(
            &subnets,
            2,
            &IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2))
        ));
    }

    #[test]
    fn multicast_loop_is_enabled() {
        // Loop on, so responders on this host hear our queries; our own
        // copies are dropped by `SentCopies`. Failure here is loud
        // (startup errors propagate).
        let std4 = create_v4_socket().unwrap().try_clone_std().unwrap();
        assert!(socket2::Socket::from(std4).multicast_loop_v4().unwrap());
        let std6 = create_v6_socket().unwrap().try_clone_std().unwrap();
        assert!(socket2::Socket::from(std6).multicast_loop_v6().unwrap());
    }

    #[test]
    fn own_copy_is_dropped_once_and_identical_foreign_query_kept() {
        // avahi on this host may send the very same query bytes from the
        // same ip:5353: one sent copy drops exactly one received copy.
        let now = Instant::now();
        let mut copies = SentCopies::default();
        let query = [0u8, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 7];
        copies.record(&query, now);
        assert!(copies.take(&query, now), "our looped-back copy");
        assert!(
            !copies.take(&query, now),
            "a second identical one is someone else's"
        );
        assert!(!copies.take(&[1, 2, 3], now), "never sent");
    }

    #[test]
    fn own_copies_expire_and_are_bounded() {
        let start = Instant::now();
        let mut copies = SentCopies::default();
        copies.record(b"old", start);
        let later = start + OWN_COPY_WINDOW + Duration::from_millis(1);
        assert!(!copies.take(b"old", later), "too old to be our loopback");
        for i in 0..=OWN_COPY_CAP {
            copies.record(&i.to_be_bytes(), later);
        }
        assert_eq!(copies.recent.len(), OWN_COPY_CAP);
        assert!(!copies.take(&0usize.to_be_bytes(), later), "oldest evicted");
        assert!(copies.take(&OWN_COPY_CAP.to_be_bytes(), later));
    }

    #[test]
    fn only_successfully_sent_copies_are_remembered() {
        let links = [("eth0".to_string(), 2u32)];
        let mut failures = SendFailures::default();
        let mut copies = SentCopies::default();
        let socket = FakeSocket::default();
        socket.failing_send.set(true);
        send_on_all_interfaces(
            &socket,
            &ptr_query(),
            Family::V6,
            &[],
            &links,
            &mut failures,
            &mut copies,
        );
        assert!(copies.recent.is_empty(), "a failed send never loops back");
        socket.failing_send.set(false);
        send_on_all_interfaces(
            &socket,
            &ptr_query(),
            Family::V6,
            &[],
            &links,
            &mut failures,
            &mut copies,
        );
        assert_eq!(copies.recent.len(), 1);
    }

    #[test]
    fn v6_socket_is_v6_only() {
        // v4 traffic belongs to the v4 socket alone: no v4-mapped
        // packets on the v6 socket, whatever the platform default.
        let std6 = create_v6_socket().unwrap().try_clone_std().unwrap();
        assert!(socket2::Socket::from(std6).only_v6().unwrap());
    }

    #[test]
    fn poll_timeout_waits_for_refresh_unless_reads_are_pending() {
        let now = Instant::now();
        let refresh = now + Duration::from_secs(7);
        assert_eq!(poll_timeout(now, refresh, false), Duration::from_secs(7));
        assert_eq!(poll_timeout(now, refresh, true), Duration::ZERO);
        // A due (or overdue) refresh never yields a zero timeout: no spin.
        assert_eq!(poll_timeout(now, now, false), Duration::from_millis(1));
        assert_eq!(
            poll_timeout(now + Duration::from_secs(1), now, false),
            Duration::from_millis(1)
        );
    }

    #[test]
    fn drain_stops_at_would_block_budget_or_closed_receiver() {
        let mut left = 3;
        let empty = drain_budgeted(10, || {
            if left == 0 {
                return ReadStep::WouldBlock;
            }
            left -= 1;
            ReadStep::Handled
        });
        assert_eq!(empty, Drained::Empty);
        let mut reads = 0;
        let capped = drain_budgeted(4, || {
            reads += 1;
            ReadStep::Handled
        });
        assert_eq!((capped, reads), (Drained::Budget, 4));
        assert_eq!(drain_budgeted(4, || ReadStep::Closed), Drained::Closed);
    }

    #[test]
    fn query_send_wakes_the_poll_and_is_drained() {
        // A queued query wakes the loop at once (no sleep to wait out)
        // and is sent exactly once.
        let mut poll = mio::Poll::new().unwrap();
        let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).unwrap());
        let (tx, rx) = mpsc::channel();
        let query_tx = QueryTx {
            tx,
            waker,
            transmit: Arc::new(TransmitState::new(true, true)),
        };
        let req = QueryRequest {
            name: "_http._tcp.local".to_string(),
            record_type: TYPE::PTR,
            known_answers: Vec::new(),
            qu: false,
        };
        assert!(query_tx.send(req.clone()));
        assert!(query_tx.send(req));
        let mut events = mio::Events::with_capacity(4);
        let started = Instant::now();
        poll.poll(&mut events, Some(Duration::from_secs(5)))
            .unwrap();
        assert!(
            events.iter().any(|e| e.token() == WAKER_TOKEN),
            "the waker fired"
        );
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "woken, not timed out"
        );
        let mut names = Vec::new();
        assert_eq!(
            drain_queries(&rx, QUERY_BUDGET, |q| names.push(q.name.clone())),
            (2, false)
        );
        assert_eq!(names, vec!["_http._tcp.local"; 2]);
        assert_eq!(
            drain_queries(&rx, QUERY_BUDGET, |_| {}),
            (0, false),
            "drained once"
        );
    }

    /// Records pin/send calls; fails the configured ones.
    #[derive(Default)]
    struct FakeSocket {
        calls: std::cell::RefCell<Vec<String>>,
        failing_pin: Option<Egress>,
        failing_send: std::cell::Cell<bool>,
    }

    impl QuerySocket for FakeSocket {
        fn pin(&self, egress: Egress) -> std::io::Result<()> {
            self.calls.borrow_mut().push(format!("pin {egress:?}"));
            if self.failing_pin == Some(egress) {
                return Err(std::io::ErrorKind::AddrNotAvailable.into());
            }
            Ok(())
        }

        fn send_to(&self, _bytes: &[u8], dest: SocketAddr) -> std::io::Result<()> {
            self.calls.borrow_mut().push(format!("send {dest}"));
            if self.failing_send.get() {
                return Err(std::io::ErrorKind::NetworkUnreachable.into());
            }
            Ok(())
        }
    }

    fn ptr_query() -> QueryRequest {
        QueryRequest {
            name: "_http._tcp.local".to_string(),
            record_type: TYPE::PTR,
            known_answers: Vec::new(),
            qu: false,
        }
    }

    #[test]
    fn each_copy_is_pinned_right_before_it_is_sent() {
        // The egress pin is socket-wide: pinning every link first would
        // send all copies out of the last one.
        let socket = FakeSocket::default();
        let links = [("eth0".to_string(), 2u32), ("wlan0".to_string(), 3u32)];
        let mut failures = SendFailures::default();
        send_on_all_interfaces(
            &socket,
            &ptr_query(),
            Family::V6,
            &[],
            &links,
            &mut failures,
            &mut SentCopies::default(),
        );
        assert_eq!(
            *socket.calls.borrow(),
            [
                "pin V6(2)",
                "send [ff02::fb%2]:5353",
                "pin V6(3)",
                "send [ff02::fb%3]:5353",
            ]
        );
    }

    #[test]
    fn failed_pin_skips_only_that_links_copy() {
        let eth0 = Ipv4Addr::new(192, 168, 1, 2);
        let wlan0 = Ipv4Addr::new(10, 0, 0, 2);
        let socket = FakeSocket {
            failing_pin: Some(Egress::V4(eth0)),
            ..FakeSocket::default()
        };
        let links = [("eth0".to_string(), eth0), ("wlan0".to_string(), wlan0)];
        let mut failures = SendFailures::default();
        send_on_all_interfaces(
            &socket,
            &ptr_query(),
            Family::V4,
            &links,
            &[],
            &mut failures,
            &mut SentCopies::default(),
        );
        assert_eq!(
            *socket.calls.borrow(),
            [
                "pin V4(192.168.1.2)",
                "pin V4(10.0.0.2)",
                "send 224.0.0.251:5353",
            ],
            "no unpinned copy leaves for eth0"
        );
        // The pin failure is on record: a second query logs nothing new.
        assert_eq!(
            failures.record_failure(
                Family::V4,
                "eth0",
                SendOp::Pin,
                std::io::ErrorKind::AddrNotAvailable
            ),
            None
        );
    }

    #[test]
    fn send_failure_is_recorded_until_the_link_recovers() {
        let socket = FakeSocket::default();
        socket.failing_send.set(true);
        let links = [("eth0".to_string(), 2u32)];
        let mut failures = SendFailures::default();
        send_on_all_interfaces(
            &socket,
            &ptr_query(),
            Family::V6,
            &[],
            &links,
            &mut failures,
            &mut SentCopies::default(),
        );
        assert_eq!(
            failures.record_failure(
                Family::V6,
                "eth0",
                SendOp::Send,
                std::io::ErrorKind::NetworkUnreachable
            ),
            None,
            "the first failure was already recorded"
        );
        socket.failing_send.set(false);
        send_on_all_interfaces(
            &socket,
            &ptr_query(),
            Family::V6,
            &[],
            &links,
            &mut failures,
            &mut SentCopies::default(),
        );
        assert_eq!(
            failures.record_success(Family::V6, "eth0"),
            None,
            "the successful send already recorded the recovery"
        );
    }

    #[test]
    fn no_usable_link_means_no_send_target() {
        // An empty list never falls back to an unpinned copy (which
        // would leave by the default interface, maybe an unselected one).
        assert!(send_targets(Family::V4, &[], &[]).is_empty());
        assert!(send_targets(Family::V6, &[], &[]).is_empty());
        let socket = FakeSocket::default();
        let mut failures = SendFailures::default();
        for family in [Family::V4, Family::V6] {
            send_on_all_interfaces(
                &socket,
                &ptr_query(),
                family,
                &[],
                &[],
                &mut failures,
                &mut SentCopies::default(),
            );
        }
        assert!(socket.calls.borrow().is_empty(), "nothing pinned or sent");
    }

    #[test]
    fn one_pinned_target_per_usable_link() {
        let v4 = [
            ("eth0".to_string(), Ipv4Addr::new(192, 168, 1, 2)),
            ("wlan0".to_string(), Ipv4Addr::new(10, 0, 0, 2)),
        ];
        let v6 = [("eth0".to_string(), 2u32)];
        let mdns_v4: SocketAddr = "224.0.0.251:5353".parse().unwrap();
        assert_eq!(
            send_targets(Family::V4, &v4, &v6),
            [
                SendTarget {
                    link: "eth0",
                    dest: mdns_v4,
                    egress: Egress::V4(Ipv4Addr::new(192, 168, 1, 2)),
                },
                SendTarget {
                    link: "wlan0",
                    dest: mdns_v4,
                    egress: Egress::V4(Ipv4Addr::new(10, 0, 0, 2)),
                },
            ]
        );
        assert_eq!(
            send_targets(Family::V6, &v4, &v6),
            [SendTarget {
                link: "eth0",
                dest: mdns_dest_v6(2),
                egress: Egress::V6(2),
            }],
            "v6 destination carries the link's scope id"
        );
    }

    #[test]
    fn pause_and_resume_log_once_per_transition() {
        use PauseLog::{Paused, Resumed};
        let state = TransmitState::new(true, true);
        // Starting with links: nothing to say.
        assert_eq!(state.update(None, Some(true)), [None, None]);
        // Links gone: one pause line, then silence while it stays empty.
        assert_eq!(state.update(None, Some(false)), [None, Some(Paused)]);
        assert_eq!(state.update(None, Some(false)), [None, None]);
        // Back: one resume line, then silence.
        assert_eq!(state.update(None, Some(true)), [None, Some(Resumed)]);
        assert_eq!(state.update(None, Some(true)), [None, None]);
        // Families are independent; starting empty logs the pause once,
        // and a closed socket (None) keeps its family as is.
        assert_eq!(state.update(Some(false), None), [Some(Paused), None]);
        assert_eq!(state.update(Some(false), None), [None, None]);
        assert_eq!(state.flags(), (false, true));
    }

    #[test]
    fn handoff_publishes_both_families_in_one_step() {
        // v4 goes down while v6 comes up in the same refresh: both
        // flags change in one store, so a reader never sees "no family".
        let state = TransmitState::new(true, false);
        assert_eq!(
            state.update(Some(false), Some(true)),
            [Some(PauseLog::Paused), Some(PauseLog::Resumed)]
        );
        assert_eq!(state.flags(), (false, true));
        assert!(state.any());
    }

    #[test]
    fn pinned_flags_ignore_listener_updates() {
        let state = TransmitState::new(true, true);
        state.pin(false, true);
        assert_eq!(state.update(Some(true), Some(false)), [None, None]);
        assert_eq!(state.flags(), (false, true));
    }

    #[test]
    fn send_failures_log_once_per_kind_until_recovery() {
        use std::io::ErrorKind::{NetworkUnreachable, PermissionDenied};
        use SendOp::{Pin, Send};
        let failed = Some(SendLog::Failed);
        let mut failures = SendFailures::default();
        // Success without a prior failure is silent.
        assert_eq!(failures.record_success(Family::V6, "eth0"), None);
        // First failure logs; a repeat of the same kind is silent.
        assert_eq!(
            failures.record_failure(Family::V6, "eth0", Send, NetworkUnreachable),
            failed
        );
        assert_eq!(
            failures.record_failure(Family::V6, "eth0", Send, NetworkUnreachable),
            None
        );
        // A different kind logs once; alternating kinds stay deduped.
        assert_eq!(
            failures.record_failure(Family::V6, "eth0", Send, PermissionDenied),
            failed
        );
        assert_eq!(
            failures.record_failure(Family::V6, "eth0", Send, NetworkUnreachable),
            None
        );
        assert_eq!(
            failures.record_failure(Family::V6, "eth0", Send, PermissionDenied),
            None
        );
        // A pin failure of an already-logged kind still logs: other call.
        assert_eq!(
            failures.record_failure(Family::V6, "eth0", Pin, NetworkUnreachable),
            failed
        );
        // Same link name, other family: its own state.
        assert_eq!(
            failures.record_failure(Family::V4, "eth0", Send, PermissionDenied),
            failed
        );
        // Success after failure logs one recovery, then silence.
        assert_eq!(
            failures.record_success(Family::V6, "eth0"),
            Some(SendLog::Recovered)
        );
        assert_eq!(failures.record_success(Family::V6, "eth0"), None);
        assert_eq!(
            failures.record_failure(Family::V6, "eth0", Send, NetworkUnreachable),
            failed
        );
    }

    #[test]
    fn send_failures_forget_pruned_links() {
        use std::io::ErrorKind::NetworkUnreachable;
        use SendOp::Send;
        let failed = Some(SendLog::Failed);
        let mut failures = SendFailures::default();
        failures.record_failure(Family::V4, "eth0", Send, NetworkUnreachable);
        failures.record_failure(Family::V4, "wlan0", Send, NetworkUnreachable);
        failures.record_failure(Family::V6, "eth0", Send, NetworkUnreachable);
        // eth0 left the v4 list; the v6 list is unaffected.
        failures.retain_links(Family::V4, ["wlan0"]);
        assert_eq!(
            failures.record_failure(Family::V4, "eth0", Send, NetworkUnreachable),
            failed
        );
        assert_eq!(
            failures.record_failure(Family::V4, "wlan0", Send, NetworkUnreachable),
            None
        );
        assert_eq!(
            failures.record_failure(Family::V6, "eth0", Send, NetworkUnreachable),
            None
        );
        // A pruned link that comes back and succeeds logs no recovery.
        failures.retain_links(Family::V4, ["wlan0"]);
        assert_eq!(failures.record_success(Family::V4, "eth0"), None);
    }

    #[test]
    fn query_drain_is_budgeted_per_pass() {
        // A query burst can't hold off socket reads: one pass sends at
        // most the budget and reports the rest as pending.
        let (tx, rx) = mpsc::channel();
        for i in 0..5 {
            tx.send(QueryRequest {
                name: format!("q{i}.local"),
                record_type: TYPE::A,
                known_answers: Vec::new(),
                qu: false,
            })
            .unwrap();
        }
        let mut sent = Vec::new();
        assert_eq!(
            drain_queries(&rx, 3, |q| sent.push(q.name.clone())),
            (3, true)
        );
        assert_eq!(
            drain_queries(&rx, 3, |q| sent.push(q.name.clone())),
            (2, false)
        );
        assert_eq!(
            sent,
            ["q0.local", "q1.local", "q2.local", "q3.local", "q4.local"]
        );
    }

    #[test]
    fn startup_needs_at_least_one_socket() {
        assert!(require_transport(true, true).is_ok());
        assert!(require_transport(true, false).is_ok());
        assert!(require_transport(false, true).is_ok());
        let err = require_transport(false, false).unwrap_err().to_string();
        assert!(err.contains("no mDNS socket"), "{err}");
    }

    #[test]
    fn listener_runs_with_one_family_missing() {
        // One family failing to open must not stop the other: a missing
        // socket is skipped by refresh and reads.
        let poll = mio::Poll::new().unwrap();
        let v4 = FamilySocket::open(Family::V4, poll.registry()).expect("v4 socket");
        let (tx, _rx) = mpsc::channel();
        let (_query_tx, query_rx) = mpsc::channel();
        let mut listener = Listener::new(
            poll,
            Some(v4),
            None,
            tx,
            query_rx,
            SharedWithApp {
                drops: Arc::new(DropStats::default()),
                transmit: Arc::new(TransmitState::new(true, false)),
            },
            Some(HashSet::new()),
        );
        listener.refresh();
        assert!(listener.ifaces_v6.is_empty());
        assert!(
            listener.read_family(Family::V6),
            "missing family is a no-op"
        );
        assert!(listener.read_family(Family::V4), "open family drains");
        assert!(listener.v4.is_some(), "socket put back after the drain");
    }

    #[test]
    fn multicast_ttl_is_255() {
        // RFC 6762 §11: mDNS packets go out with TTL 255.
        let std4 = create_v4_socket().unwrap().try_clone_std().unwrap();
        assert_eq!(socket2::Socket::from(std4).multicast_ttl_v4().unwrap(), 255);
        let std6 = create_v6_socket().unwrap().try_clone_std().unwrap();
        assert_eq!(
            socket2::Socket::from(std6).multicast_hops_v6().unwrap(),
            255
        );
    }

    #[test]
    fn malformed_packets_are_counted_with_source() {
        let drops = DropStats::default();
        assert_eq!(drops.malformed_total(), 0);
        assert!(drops.malformed_last().is_none());
        drops.note_malformed(test_source());
        drops.note_malformed(test_source());
        assert_eq!(drops.malformed_total(), 2);
        assert_eq!(drops.malformed_last().unwrap().0, test_source());
        // Off-link accounting is untouched by malformed traffic.
        assert_eq!(drops.total(), 0);
        assert!(drops.last().is_none());
    }

    #[test]
    fn link_stats_lists_are_sorted_and_disjoint() {
        let stats = link_stats(None);
        let mut v4 = stats.v4.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
        let mut sorted = v4.clone();
        sorted.sort();
        assert_eq!(v4, sorted);
        // Usable links are never reported as skipped/inactive.
        for name in &v4 {
            assert!(!stats.skipped.contains(name));
            assert!(!stats.inactive.contains(name));
        }
        v4 = stats.v6.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
        sorted = v4.clone();
        sorted.sort();
        assert_eq!(v4, sorted);
    }

    #[test]
    fn link_stats_selection_confines_usable_to_selected() {
        // Whatever this machine has, a selection must only ever report
        // selected names as usable and never as skipped: display and
        // transport join set cannot contradict each other.
        let sel = HashSet::from(["br0".to_string(), "eth0".to_string(), "lo".to_string()]);
        let stats = link_stats(Some(&sel));
        for (name, _) in &stats.v4 {
            assert!(sel.contains(name), "usable {name} not selected");
        }
        for (name, _) in &stats.v6 {
            assert!(sel.contains(name), "usable {name} not selected");
        }
        for name in &stats.skipped {
            assert!(!sel.contains(name), "selected {name} reported skipped");
        }
        let mut skipped = stats.skipped.clone();
        skipped.sort();
        assert_eq!(stats.skipped, skipped);
        let mut inactive = stats.inactive.clone();
        inactive.sort();
        assert_eq!(stats.inactive, inactive);
    }

    #[test]
    fn selection_unset_allows_every_link() {
        assert!(interface_selected("br0", None));
        assert!(interface_selected("eth0", None));
        assert!(interface_selected("", None));
    }

    #[test]
    fn selection_set_restricts_to_named_links() {
        let sel = HashSet::from(["br0".to_string()]);
        assert!(interface_selected("br0", Some(&sel)));
        assert!(!interface_selected("eth0", Some(&sel)));
        // Unmapped ingress never matches a selection: fail closed.
        assert!(!interface_selected("", Some(&sel)));
    }

    #[test]
    fn join_candidate_explicit_selection_overrides_skip_policy() {
        let lo = HashSet::from(["lo".to_string()]);
        // Explicitly selected loopback joins when usable ...
        assert!(join_candidate("lo", true, Some(&lo)));
        // ... while unselected usable links do not.
        assert!(!join_candidate("eth0", true, Some(&lo)));
        // Unfiltered behavior is unchanged.
        assert!(!join_candidate("lo", true, None));
        assert!(join_candidate("eth0", true, None));
        // Down links never join: the periodic refresh picks them up when up.
        let br0 = HashSet::from(["br0".to_string()]);
        assert!(!join_candidate("br0", false, Some(&br0)));
        assert!(!join_candidate("eth0", false, None));
        // Container skips still apply without a filter.
        assert!(!join_candidate("docker0", true, None));
        assert!(!join_candidate("veth1234", true, None));
    }

    #[test]
    fn validate_selection_accepts_known_names_deduped() {
        let available = HashSet::from(["br0".to_string(), "eth0".to_string()]);
        let got = validate_selection(
            &["br0".to_string(), "eth0".to_string(), "br0".to_string()],
            &available,
        )
        .unwrap();
        assert_eq!(got, HashSet::from(["br0".to_string(), "eth0".to_string()]));
    }

    #[test]
    fn validate_selection_rejects_unknown_with_available_list() {
        let available = HashSet::from(["br0".to_string(), "eth0".to_string()]);
        let err =
            validate_selection(&["br0".to_string(), "nope".to_string()], &available).unwrap_err();
        let msg = err.to_string();
        assert!(msg.contains("'nope'"), "got: {msg}");
        assert!(msg.contains("br0, eth0"), "got: {msg}");
    }
}
