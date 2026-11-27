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
pub(crate) use wire::display_rdata;
pub(crate) use wire::escape_label;
pub(crate) use wire::escapes_next;
pub(crate) use wire::instance_name;
pub(crate) use wire::is_local_name;
pub(crate) use wire::is_proto_label;
pub(crate) use wire::is_sub_label;
pub(crate) use wire::nsec_address_types;
pub(crate) use wire::parse_packet;
pub(crate) use wire::presentation_labels;
pub use wire::question_fields;
pub use wire::record_fields;
pub use wire::record_type_from_u16;
pub(crate) use wire::rtype_from_str;
pub(crate) use wire::rtype_label;
pub(crate) use wire::rtype_name;
pub(crate) use wire::strip_local_suffix;
pub(crate) use wire::unescape_name;
pub(crate) use wire::wire_rdata_len;
use wire::WireSink;
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

    /// Short label for the Answers pane's SECT column (#399). Known
    /// answers and questions never reach that pane; they still get a
    /// label rather than a panic.
    pub fn short_label(self) -> &'static str {
        match self {
            RecordSection::Answer => "ans",
            RecordSection::Authority => "auth",
            RecordSection::Additional => "add",
            RecordSection::KnownAnswer => "ka",
            RecordSection::Question => "q",
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
    /// Digest of an out-of-scope record's rdata bytes, which are never
    /// kept (`rdata` shows only `rdlength=<n>`): enough to tell a repeat
    /// from changed content of one length (an SOA serial bump) without
    /// holding or interpreting the data. `None` for in-scope records,
    /// whose `rdata` already names their content.
    pub rdata_digest: Option<u64>,
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
    /// Authority-section records of a query packet: a probe's proposed
    /// records (RFC 6762 §8.1). Never filed; a non-empty list marks the
    /// query as a probe, which the rate checks exempt (#408, #407).
    pub query_authority: Vec<RawRecord>,
    /// Additional-section records of a query packet, EDNS0 OPT left out.
    /// Known answers belong in the Answer section (RFC 6762 §7.1), so
    /// these suppress nothing: never filed, never known answers for §7.3,
    /// only flagged (`misplaced-known-answer`, #424).
    pub query_additional: Vec<RawRecord>,
    /// DNS header response code for a response packet; queries are `None`.
    pub rcode: Option<u8>,
    pub received_at: Instant,
    pub raw_bytes: Vec<u8>,
    pub source: SocketAddr,
}

impl Event {
    /// Whether this is a probe query (RFC 6762 §8.1): it carries the
    /// records it proposes in the authority section. A question alone,
    /// even ANY, doesn't make a probe here, and neither does a stray OPT
    /// pseudo-record (its place is the additional section): it proposes
    /// nothing.
    pub fn is_probe(&self) -> bool {
        self.query_authority
            .iter()
            .any(|r| r.rtype != wire::OPT_TYPE)
    }

    /// Whether this is a query with the Authoritative Answer bit set,
    /// which RFC 6762 §18.4 forbids (MUST be zero in queries, ignored on
    /// reception). Read from the header's flags byte: QR clear, AA set.
    pub fn is_authoritative_query(&self) -> bool {
        self.raw_bytes
            .get(2)
            .is_some_and(|flags| flags & 0x80 == 0 && flags & 0x04 != 0)
    }
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
    /// `None` only while dropping: closing it stops the listener.
    tx: Option<mpsc::Sender<QueryRequest>>,
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
    /// A sender whose listener is gone (its queue closed), with both
    /// families able to transmit: every `send` fails, as after the
    /// listener thread stopped.
    #[cfg(test)]
    pub(crate) fn disconnected() -> Self {
        let poll = mio::Poll::new().expect("poll");
        let waker = Arc::new(mio::Waker::new(poll.registry(), WAKER_TOKEN).expect("waker"));
        let (tx, _closed) = mpsc::channel();
        Self {
            tx: Some(tx),
            waker,
            transmit: Arc::new(TransmitState::new(true, true)),
        }
    }

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
        if self.tx.as_ref().is_none_or(|tx| tx.send(req).is_err()) {
            return false;
        }
        if let Err(e) = self.waker.wake() {
            log::warn!("mex: cannot wake listener: {e}");
        }
        true
    }
}

/// Dropping the sender stops the listener: the closed queue is seen on
/// the wake, so the thread exits and closes its sockets with the app
/// instead of on the next datagram, which may never come.
impl Drop for QueryTx {
    fn drop(&mut self) {
        drop(self.tx.take());
        if let Err(e) = self.waker.wake() {
            log::warn!("mex: cannot wake listener to stop: {e}");
        }
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
        waker: waker.clone(),
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
            tx: Some(query_tx),
            waker,
            transmit,
        },
        rx,
        drops,
    ))
}

#[cfg(test)]
mod tests;
