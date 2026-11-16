// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicU8, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use simple_dns::{
    rdata::RData, Packet, PacketFlag, Question, ResourceRecord, CLASS, QCLASS, QTYPE, TYPE,
};

/// Whether a parsed DNS name holds bytes outside UTF-8. Must run on
/// raw label bytes at parse time: after lossy display a genuine U+FFFD
/// character and invalid bytes are indistinguishable.
fn name_has_invalid_utf8(name: &simple_dns::Name<'_>) -> bool {
    name.get_labels()
        .iter()
        .any(|l| std::str::from_utf8(l.as_ref()).is_err())
}

/// Whether name-valued rdata holds non-UTF-8 bytes: the same set of
/// variants `rdata_label` renders as names. TXT values and HINFO strings
/// are excluded on purpose (opaque binary is legitimate there, and they
/// never become refresh query names). Only in-scope answer types are
/// decoded at all (`anomalies::is_mdns_answer_type`).
fn rdata_has_invalid_utf8(rdata: &RData) -> bool {
    // Each name-wrapper is its own type, so the arms cannot share one
    // binding; every arm just asks the same question of its names.
    match rdata {
        RData::PTR(n) => name_has_invalid_utf8(n),
        RData::CNAME(n) => name_has_invalid_utf8(n),
        RData::NS(n) => name_has_invalid_utf8(n),
        RData::SRV(srv) => name_has_invalid_utf8(&srv.target),
        RData::NSEC(nsec) => name_has_invalid_utf8(&nsec.next_name),
        _ => false,
    }
}

/// Display form of a parsed DNS name: labels joined as UTF-8 (lossy),
/// with a trailing dot. Non-UTF-8 bytes render as U+FFFD (RFC 6762 §16
/// names are UTF-8); this matches the in-flight instance-name fix and
/// replaces the old latin-1 byte-as-char rendering. Labels go on the
/// wire as raw bytes, so this deliberately does not interpret escapes:
/// a dot inside a DNS-SD instance label (RFC 6763 §4.1.1) renders as a
/// plain separator, the same ambiguous-but-stable form the old codec
/// produced after unescaping presentation format. `split_instance_labels`
/// below recovers the label split for re-encoding.
fn display_name(name: &simple_dns::Name<'_>) -> String {
    let mut out = String::new();
    for (i, label) in name.get_labels().iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(&String::from_utf8_lossy(label.as_ref()));
    }
    out.push('.');
    out
}
use socket2::{Domain, SockAddr};
use socket_pktinfo::PktInfoUdpSocket;

const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const MDNS_PORT: u16 = 5353;
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

/// What a send outcome means for the log, after dedup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SendLog {
    /// First failure of this kind on this link: log it at error.
    Failed,
    /// The link sent successfully after failing: log one recovery line.
    Recovered,
}

/// The socket call a send-path failure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum SendOp {
    /// Pinning the multicast egress interface.
    Pin,
    /// Sending the query copy.
    Send,
}

/// Send-failure dedup per (family, link): a broken link logs each
/// (operation, error kind) once until it sends successfully again, then
/// logs one recovery line, instead of once per query. Links that leave
/// the interface list forget their state.
#[derive(Debug, Default)]
struct SendFailures {
    failing: HashMap<(Family, String), HashSet<(SendOp, std::io::ErrorKind)>>,
}

impl SendFailures {
    /// Record a failed pin or send on `iface`, returning `Failed` the
    /// first time this (operation, kind) fails since the link last sent.
    fn record_failure(
        &mut self,
        family: Family,
        iface: &str,
        op: SendOp,
        kind: std::io::ErrorKind,
    ) -> Option<SendLog> {
        self.failing
            .entry((family, iface.to_string()))
            .or_default()
            .insert((op, kind))
            .then_some(SendLog::Failed)
    }

    /// Record a successful send on `iface`, returning `Recovered` when
    /// the link had failed since its last successful send.
    fn record_success(&mut self, family: Family, iface: &str) -> Option<SendLog> {
        self.failing
            .remove(&(family, iface.to_string()))
            .map(|_| SendLog::Recovered)
    }

    /// Forget links of `family` no longer in `links`.
    fn retain_links<'a>(&mut self, family: Family, links: impl IntoIterator<Item = &'a str>) {
        let keep: HashSet<&str> = links.into_iter().collect();
        self.failing
            .retain(|(f, name), _| *f != family || keep.contains(name.as_str()));
    }
}

/// The interface a query copy is pinned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Egress {
    V4(Ipv4Addr),
    V6(u32),
}

/// The two socket calls the send path makes, so the per-link pin/send
/// sequence can be checked without a network.
trait QuerySocket {
    /// Pin the multicast egress interface (socket-wide).
    fn pin(&self, egress: Egress) -> std::io::Result<()>;
    fn send_to(&self, bytes: &[u8], dest: SocketAddr) -> std::io::Result<()>;
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

/// One query copy: the link it leaves on, its destination, and the
/// egress interface pinned for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SendTarget<'a> {
    link: &'a str,
    dest: SocketAddr,
    egress: Egress,
}

/// One target per usable link of `family`. An empty list means no
/// target at all: no copy is sent unpinned (it would leave by the
/// kernel's default multicast interface, possibly one the user did not
/// select). The interface refresh picks links up again once they gain
/// an address or come up.
fn send_targets<'a>(
    family: Family,
    ifaces_v4: &'a [(String, Ipv4Addr)],
    ifaces_v6: &'a [(String, u32)],
) -> Vec<SendTarget<'a>> {
    match family {
        Family::V4 => ifaces_v4
            .iter()
            .map(|(name, ip)| SendTarget {
                link: name,
                dest: SocketAddr::from(SocketAddrV4::new(MDNS_V4, MDNS_PORT)),
                egress: Egress::V4(*ip),
            })
            .collect(),
        Family::V6 => ifaces_v6
            .iter()
            .map(|(name, idx)| SendTarget {
                link: name,
                dest: mdns_dest_v6(*idx),
                egress: Egress::V6(*idx),
            })
            .collect(),
    }
}

/// A transmit-state change worth one log line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PauseLog {
    /// The family's link list became empty: its queries stop.
    Paused,
    /// The family has a usable link again: its queries resume.
    Resumed,
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

pub fn local_ips() -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        out.insert(iface.addr.ip());
    }
    out
}

/// Snapshot of usable vs skipped links for the metrics view. Refreshed on
/// demand from `if_addrs` (same source as the listener joins), so the App
/// thread sees link changes without new thread communication.
#[derive(Debug, Clone, Default)]
pub struct LinkStats {
    /// Usable v4 links: (interface name, address).
    pub v4: Vec<(String, Ipv4Addr)>,
    /// Usable v6 links: (interface name, index).
    pub v6: Vec<(String, u32)>,
    /// Distinct names skipped by policy (`lo`/`docker`/`veth`), or
    /// excluded by an explicit interface selection.
    pub skipped: Vec<String>,
    /// Distinct names that are down or point-to-point (no multicast).
    pub inactive: Vec<String>,
}

/// Effective join set for the metrics view: usable links under the
/// default skip policy, or the selected usable links under an explicit
/// selection (which overrides the policy). Unselected usable links are
/// reported as skipped so the snapshot still enumerates every link.
pub fn link_stats(selection: Option<&HashSet<String>>) -> LinkStats {
    let mut stats = LinkStats::default();
    let mut seen_v4 = HashSet::new();
    let mut seen_v6 = HashSet::new();
    let mut seen_skipped = HashSet::new();
    let mut seen_inactive = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        let usable = usable_interface(&iface);
        if !join_candidate(&iface.name, usable, selection) {
            // Not joined: policy skip, selection exclusion (usable links
            // only), or unusable. A selected-but-down link lands in
            // inactive, visibly waiting for the rejoin refresh.
            if skipped_interface(&iface.name) || (usable && selection.is_some()) {
                if seen_skipped.insert(iface.name.clone()) {
                    stats.skipped.push(iface.name.clone());
                }
            } else if seen_inactive.insert(iface.name.clone()) {
                stats.inactive.push(iface.name.clone());
            }
            continue;
        }
        match iface.addr {
            if_addrs::IfAddr::V4(v4) => {
                if seen_v4.insert(iface.name.clone()) {
                    stats.v4.push((iface.name.clone(), v4.ip));
                }
            }
            if_addrs::IfAddr::V6(v6) => {
                if v6.ip.to_string().starts_with('f') && seen_v6.insert(iface.name.clone()) {
                    stats
                        .v6
                        .push((iface.name.clone(), iface.index.unwrap_or(0)));
                }
            }
        }
    }
    stats.v4.sort_by(|a, b| a.0.cmp(&b.0));
    stats.v6.sort_by(|a, b| a.0.cmp(&b.0));
    stats.skipped.sort();
    stats.inactive.sort();
    stats
}

/// Per-link ingress data in one if-addrs pass: index → name plus
/// index → [(address, netmask)] for the RFC 6762 §11 locality test.
/// Unfiltered on purpose: locality labeling and subnet checks must see
/// every link, including ones skipped for multicast joins.
type SubnetMap = HashMap<u32, Vec<(IpAddr, IpAddr)>>;

fn link_maps() -> (HashMap<u32, String>, SubnetMap) {
    let mut names = HashMap::new();
    let mut subnets: SubnetMap = HashMap::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        let Some(idx) = iface.index else { continue };
        names.entry(idx).or_insert_with(|| iface.name.clone());
        let (addr, mask) = match iface.addr {
            if_addrs::IfAddr::V4(v4) => (IpAddr::V4(v4.ip), IpAddr::V4(v4.netmask)),
            if_addrs::IfAddr::V6(v6) => (IpAddr::V6(v6.ip), IpAddr::V6(v6.netmask)),
        };
        subnets.entry(idx).or_default().push((addr, mask));
    }
    (names, subnets)
}

/// Fill gaps in the cached link maps: the interface may have appeared
/// since the last 10s refresh. Re-queries if-addrs once per unknown
/// index (remembered in `unknown` until the next refresh) so a
/// permanently unmapped index costs one scan, not one per packet.
/// The scan is injected for testing; the listener passes `link_maps`.
fn backfill_link(
    ifindex: u32,
    ifnames: &mut HashMap<u32, String>,
    subnets: &mut SubnetMap,
    unknown: &mut HashSet<u32>,
    scan: &dyn Fn() -> (HashMap<u32, String>, SubnetMap),
) {
    if !unknown.insert(ifindex) {
        return;
    }
    let (names, nets) = scan();
    if let Some(name) = names.get(&ifindex) {
        ifnames.insert(ifindex, name.clone());
    }
    if let Some(net) = nets.get(&ifindex) {
        subnets.insert(ifindex, net.clone());
    }
}

/// The two mDNS link-local multicast destinations (RFC 6762 §3).
fn mdns_multicast_dest(dst: &IpAddr) -> bool {
    *dst == IpAddr::V4(MDNS_V4) || *dst == IpAddr::V6(MDNS_V6)
}

/// RFC 6762 §11 locality test for unicast-destination packets: the
/// source shares a local subnet ((I&M)==(P&M)) on the ingress link.
/// Unknown links and family mismatches fail closed (refuse).
fn source_on_link(subnets: &SubnetMap, ifindex: u32, src: &IpAddr) -> bool {
    let Some(nets) = subnets.get(&ifindex) else {
        return false;
    };
    nets.iter().any(|(addr, mask)| match (addr, mask, src) {
        (IpAddr::V4(i), IpAddr::V4(m), IpAddr::V4(p)) => {
            u32::from_be_bytes(i.octets()) & u32::from_be_bytes(m.octets())
                == u32::from_be_bytes(p.octets()) & u32::from_be_bytes(m.octets())
        }
        (IpAddr::V6(i), IpAddr::V6(m), IpAddr::V6(p)) => {
            u128::from_be_bytes(i.octets()) & u128::from_be_bytes(m.octets())
                == u128::from_be_bytes(p.octets()) & u128::from_be_bytes(m.octets())
        }
        _ => false,
    })
}

/// Whether an interface is usable for mDNS: it must be operationally
/// up, and point-to-point links are skipped (they have no multicast
/// group to browse). Sourced from if-addrs so this stays cross-platform.
fn usable_interface(iface: &if_addrs::Interface) -> bool {
    !iface.is_p2p() && iface.is_oper_up()
}

fn skipped_interface(name: &str) -> bool {
    name == "lo" || name.starts_with("docker") || name.starts_with("veth")
}

/// All OS interface names in any state (up, down, point-to-point): the
/// validation universe for an explicit selection. Down links validate
/// fine and are picked up by the periodic rejoin once they come up.
pub fn available_interfaces() -> HashSet<String> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .iter()
        .map(|i| i.name.clone())
        .collect()
}

/// Validate an explicit `-i/--interfaces` selection: every name must
/// exist, otherwise abort listing the sorted available names (same
/// shape as the sibling browser). Returns the deduped set.
pub fn validate_selection(
    requested: &[String],
    available: &HashSet<String>,
) -> Result<HashSet<String>> {
    let mut sorted: Vec<&String> = available.iter().collect();
    sorted.sort();
    for name in requested {
        if !available.contains(name) {
            anyhow::bail!(
                "Interface '{name}' not found. Available interfaces: {}",
                sorted
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(requested.iter().cloned().collect())
}

/// Whether ingress from `name` is kept under an explicit selection:
/// unset keeps every link, set keeps only named ones. Unmapped ingress
/// (empty name) fails closed under a selection.
fn interface_selected(name: &str, selection: Option<&HashSet<String>>) -> bool {
    selection.is_none_or(|sel| sel.contains(name))
}

/// Whether a link is a multicast-join candidate: an explicit selection
/// overrides the loopback/container skip policy (user intent wins) but
/// still requires the link to be usable; down links wait for the
/// periodic refresh instead of erroring.
fn join_candidate(name: &str, usable: bool, selection: Option<&HashSet<String>>) -> bool {
    if !usable {
        return false;
    }
    match selection {
        Some(sel) => sel.contains(name),
        None => !skipped_interface(name),
    }
}

fn v4_interfaces(selection: Option<&HashSet<String>>) -> Vec<(String, Ipv4Addr)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if !join_candidate(&iface.name, usable_interface(&iface), selection) {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = iface.addr {
            // Join once per interface: extra addresses share the group.
            if seen.insert(iface.name.clone()) {
                out.push((iface.name, v4.ip));
            }
        }
    }
    out
}

fn v6_interfaces(selection: Option<&HashSet<String>>) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if !join_candidate(&iface.name, usable_interface(&iface), selection) {
            continue;
        }
        if let if_addrs::IfAddr::V6(v6) = iface.addr {
            // Join once per interface: extra addresses share the group.
            if v6.ip.to_string().starts_with('f') && seen.insert(iface.name.clone()) {
                out.push((iface.name, iface.index.unwrap_or(0)));
            }
        }
    }
    out
}

fn create_v4_socket() -> Result<PktInfoUdpSocket> {
    let socket = PktInfoUdpSocket::new(Domain::IPV4)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    // Querier-only: our own transmissions must not loop back and be
    // re-ingested as sightings (suppression already ignores self, and
    // the Questions pane has no use for our own queries either).
    socket.set_multicast_loop_v4(false)?;
    // RFC 6762 §11 sends with IP TTL 255 (a SHOULD for responses, and
    // ecosystem convention for queries too): link-local scope is
    // unaffected, but legacy checkers discard anything else.
    socket.set_multicast_ttl_v4(255)?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    socket.bind(&addr.into())?;
    Ok(socket)
}

fn create_v6_socket() -> Result<PktInfoUdpSocket> {
    let socket = PktInfoUdpSocket::new(Domain::IPV6)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.set_multicast_loop_v6(false)?;
    socket.set_multicast_hops_v6(255)?;
    // v6 only: v4 traffic belongs to the v4 socket alone. The pktinfo
    // wrapper has no setter, so set it through a duplicate handle (same
    // underlying socket) before bind; platform defaults differ (Linux
    // and macOS dual-stack, Windows v6-only).
    socket2::SockRef::from(&socket.try_clone_std()?).set_only_v6(true)?;
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
    socket.bind(&addr.into())?;
    Ok(socket)
}

/// mDNS destination for one interface: link-local multicast needs the
/// egress interface's scope id, otherwise the packet leaves via whatever
/// the kernel picks as the default multicast interface (or fails).
fn mdns_dest_v6(ifindex: u32) -> SocketAddr {
    SocketAddr::from(SocketAddrV6::new(MDNS_V6, MDNS_PORT, 0, ifindex))
}

/// Poll tokens: one per family socket, plus the query waker.
const V4_TOKEN: mio::Token = mio::Token(0);
const V6_TOKEN: mio::Token = mio::Token(1);
const WAKER_TOKEN: mio::Token = mio::Token(2);

/// Datagrams read from one socket per loop pass before the other gets
/// its turn, so a burst on one family can't starve the other.
const READ_BUDGET: usize = 64;

/// One family's socket: the pktinfo socket does every read (ingress
/// interface) and send; a duplicate of the same socket is registered
/// with the poll for readiness only, as mdns-sd does.
struct FamilySocket {
    family: Family,
    token: mio::Token,
    pktinfo: PktInfoUdpSocket,
    readiness: mio::net::UdpSocket,
    /// The last pass stopped at `READ_BUDGET`: more may be waiting, and
    /// edge-triggered readiness won't announce it again.
    pending: bool,
}

impl FamilySocket {
    fn open(family: Family, registry: &mio::Registry) -> Option<Self> {
        let (label, token) = match family {
            Family::V4 => ("v4", V4_TOKEN),
            Family::V6 => ("v6", V6_TOKEN),
        };
        let opened = (|| -> Result<Self> {
            let pktinfo = match family {
                Family::V4 => create_v4_socket()?,
                Family::V6 => create_v6_socket()?,
            };
            let mut readiness = mio::net::UdpSocket::from_std(pktinfo.try_clone_std()?);
            registry.register(&mut readiness, token, mio::Interest::READABLE)?;
            Ok(Self {
                family,
                token,
                pktinfo,
                readiness,
                pending: false,
            })
        })();
        match opened {
            Ok(socket) => Some(socket),
            Err(e) => {
                log::error!("mex: {label} socket: {e}");
                None
            }
        }
    }
}

/// How one budgeted drain of a socket ended.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Drained {
    /// Read until `WouldBlock` (or an error): re-arm readiness.
    Empty,
    /// Stopped at the budget: more may be waiting.
    Budget,
    /// The event receiver is gone: the app has stopped.
    Closed,
}

/// One read attempt, as the drain sees it.
enum ReadStep {
    /// A datagram was read and handled; keep going.
    Handled,
    /// Nothing more to read right now.
    WouldBlock,
    /// The event receiver is gone.
    Closed,
}

/// Read up to `budget` datagrams with `read`, stopping early on
/// `WouldBlock` or a closed receiver.
fn drain_budgeted(budget: usize, mut read: impl FnMut() -> ReadStep) -> Drained {
    for _ in 0..budget {
        match read() {
            ReadStep::Handled => {}
            ReadStep::WouldBlock => return Drained::Empty,
            ReadStep::Closed => return Drained::Closed,
        }
    }
    Drained::Budget
}

/// Poll timeout: zero while a socket has unread datagrams left over
/// from its budget, else the time until the next interface refresh,
/// at least 1 ms so a due refresh never spins.
fn poll_timeout(now: Instant, next_refresh: Instant, pending: bool) -> Duration {
    if pending {
        return Duration::ZERO;
    }
    next_refresh
        .saturating_duration_since(now)
        .max(Duration::from_millis(1))
}

/// mex can do nothing without a socket: with neither family open,
/// startup fails instead of running a listener that can never receive
/// (or shut down) while queries vanish. One open family is enough.
fn require_transport(v4_open: bool, v6_open: bool) -> Result<()> {
    if v4_open || v6_open {
        Ok(())
    } else {
        Err(anyhow::anyhow!(
            "no mDNS socket could be opened (neither IPv4 nor IPv6)"
        ))
    }
}

/// Queries sent per loop pass before the sockets get their turn, so a
/// burst of queries can't hold off reads (and overflow receive buffers).
const QUERY_BUDGET: usize = 64;

/// Send up to `budget` queued queries. Returns how many were sent and
/// whether more may be waiting (the budget was reached). Wakes may
/// coalesce, so the queue is drained on every pass.
fn drain_queries(
    rx: &mpsc::Receiver<QueryRequest>,
    budget: usize,
    mut send: impl FnMut(&QueryRequest),
) -> (usize, bool) {
    let mut sent = 0;
    while sent < budget {
        let Ok(req) = rx.try_recv() else {
            return (sent, false);
        };
        send(&req);
        sent += 1;
    }
    (sent, true)
}

/// State the listener updates and the app thread reads.
struct SharedWithApp {
    drops: Arc<DropStats>,
    transmit: Arc<TransmitState>,
}

/// The single listener: one thread, one poll loop over both family
/// sockets and the query waker. Per-link state (interface lists, name
/// and subnet maps) is shared by both families and refreshed once per
/// `IFACE_REFRESH`, which also bounds the poll timeout: an idle network
/// wakes the thread once per refresh.
struct Listener {
    poll: mio::Poll,
    v4: Option<FamilySocket>,
    v6: Option<FamilySocket>,
    tx: mpsc::Sender<Event>,
    query_rx: mpsc::Receiver<QueryRequest>,
    drops: Arc<DropStats>,
    selection: Option<HashSet<String>>,
    ifaces_v4: Vec<(String, Ipv4Addr)>,
    ifaces_v6: Vec<(String, u32)>,
    ifnames: HashMap<u32, String>,
    subnets: SubnetMap,
    unknown: HashSet<u32>,
    next_refresh: Instant,
    /// The last pass stopped at `QUERY_BUDGET`: more may be queued,
    /// and the waker won't announce them again.
    queries_pending: bool,
    send_failures: SendFailures,
    transmit: Arc<TransmitState>,
    buf: Vec<u8>,
}

impl Listener {
    fn new(
        poll: mio::Poll,
        v4: Option<FamilySocket>,
        v6: Option<FamilySocket>,
        tx: mpsc::Sender<Event>,
        query_rx: mpsc::Receiver<QueryRequest>,
        shared: SharedWithApp,
        selection: Option<HashSet<String>>,
    ) -> Self {
        let SharedWithApp { drops, transmit } = shared;
        Self {
            poll,
            v4,
            v6,
            tx,
            query_rx,
            drops,
            selection,
            ifaces_v4: Vec::new(),
            ifaces_v6: Vec::new(),
            ifnames: HashMap::new(),
            subnets: HashMap::new(),
            unknown: HashSet::new(),
            next_refresh: Instant::now(),
            queries_pending: false,
            send_failures: SendFailures::default(),
            transmit,
            buf: vec![0u8; 65535],
        }
    }

    fn run(&mut self) {
        let mut events = mio::Events::with_capacity(16);
        loop {
            if Instant::now() >= self.next_refresh {
                self.refresh();
                self.next_refresh = Instant::now() + IFACE_REFRESH;
            }
            self.send_queued();
            // Sockets left over from a budget-capped pass go first.
            for family in [Family::V4, Family::V6] {
                if self.socket(family).is_some_and(|s| s.pending) && !self.read_family(family) {
                    return;
                }
            }
            let pending = self.queries_pending
                || [&self.v4, &self.v6]
                    .into_iter()
                    .flatten()
                    .any(|s| s.pending);
            let timeout = poll_timeout(Instant::now(), self.next_refresh, pending);
            if let Err(e) = self.poll.poll(&mut events, Some(timeout)) {
                if e.kind() != std::io::ErrorKind::Interrupted {
                    log::error!("mex: poll error: {e}");
                    thread::sleep(Duration::from_secs(1));
                }
                continue;
            }
            for event in &events {
                let family = match event.token() {
                    V4_TOKEN => Family::V4,
                    V6_TOKEN => Family::V6,
                    // Queries are sent at the top of every pass.
                    _ => continue,
                };
                if !self.read_family(family) {
                    return;
                }
            }
        }
    }

    fn socket(&self, family: Family) -> Option<&FamilySocket> {
        match family {
            Family::V4 => self.v4.as_ref(),
            Family::V6 => self.v6.as_ref(),
        }
    }

    /// Recompute both families' interface lists and the shared link
    /// maps, and (re)join the mDNS group on every listed link. Joins run
    /// unconditionally every pass: they are idempotent, and a rejoin is
    /// required after an interface went away and came back (same name,
    /// new incarnation).
    fn refresh(&mut self) {
        log::debug!("mex: refreshing interface list");
        (self.ifnames, self.subnets) = link_maps();
        self.unknown.clear();
        if let Some(socket) = &self.v4 {
            self.ifaces_v4 = v4_interfaces(self.selection.as_ref());
            for (name, ip) in &self.ifaces_v4 {
                if let Err(e) = socket.pktinfo.join_multicast_v4(&MDNS_V4, ip) {
                    // Duplicate joins report AddrInUse; the membership
                    // is already in place, so only log real failures.
                    if e.kind() != std::io::ErrorKind::AddrInUse {
                        log::warn!("mex: v4 mcast {name}: {e}");
                    }
                }
            }
        }
        if let Some(socket) = &self.v6 {
            self.ifaces_v6 = v6_interfaces(self.selection.as_ref());
            for (name, idx) in &self.ifaces_v6 {
                if let Err(e) = socket.pktinfo.join_multicast_v6(&MDNS_V6, *idx) {
                    if e.kind() != std::io::ErrorKind::AddrInUse {
                        log::warn!("mex: v6 mcast {name}: {e}");
                    }
                }
            }
        }
        // Links gone from the lists forget their send-failure state.
        self.send_failures.retain_links(
            Family::V4,
            self.ifaces_v4.iter().map(|(name, _)| name.as_str()),
        );
        self.send_failures.retain_links(
            Family::V6,
            self.ifaces_v6.iter().map(|(name, _)| name.as_str()),
        );
        // A family with an open socket but no usable link sends nothing;
        // publish both families in one step and log each pause and
        // resume once.
        let v4 = self.v4.as_ref().map(|_| !self.ifaces_v4.is_empty());
        let v6 = self.v6.as_ref().map(|_| !self.ifaces_v6.is_empty());
        let transitions = self.transmit.update(v4, v6);
        for (family, transition) in [Family::V4, Family::V6].into_iter().zip(transitions) {
            let label = family.label();
            match transition {
                Some(PauseLog::Paused) => {
                    log::info!("mex: no usable {label} interface; {label} queries paused")
                }
                Some(PauseLog::Resumed) => {
                    log::info!("mex: {label} interface usable again; {label} queries resumed")
                }
                None => {}
            }
        }
    }

    /// Send queued queries (up to the budget) on each open family.
    fn send_queued(&mut self) {
        let Self {
            v4,
            v6,
            query_rx,
            ifaces_v4,
            ifaces_v6,
            send_failures,
            ..
        } = self;
        let (_, more) = drain_queries(query_rx, QUERY_BUDGET, |req| {
            for socket in [v4.as_ref(), v6.as_ref()].into_iter().flatten() {
                send_on_all_interfaces(
                    &socket.pktinfo,
                    req,
                    socket.family,
                    ifaces_v4,
                    ifaces_v6,
                    send_failures,
                );
            }
        });
        self.queries_pending = more;
    }

    /// Drain one family's socket within the budget. Re-arms readiness
    /// once it is empty (as mdns-sd does; this keeps Windows readiness
    /// right too). Returns `false` when the app has stopped.
    fn read_family(&mut self, family: Family) -> bool {
        let Some(mut socket) = (match family {
            Family::V4 => self.v4.take(),
            Family::V6 => self.v6.take(),
        }) else {
            return true;
        };
        let drained = drain_budgeted(READ_BUDGET, || self.read_one(&socket.pktinfo));
        socket.pending = drained == Drained::Budget;
        if drained == Drained::Empty {
            if let Err(e) = self.poll.registry().reregister(
                &mut socket.readiness,
                socket.token,
                mio::Interest::READABLE,
            ) {
                log::error!("mex: re-arming {family:?} socket: {e}");
            }
        }
        match family {
            Family::V4 => self.v4 = Some(socket),
            Family::V6 => self.v6 = Some(socket),
        }
        drained != Drained::Closed
    }

    /// Read and handle one datagram.
    fn read_one(&mut self, socket: &PktInfoUdpSocket) -> ReadStep {
        let (len, info) = match socket.recv(&mut self.buf) {
            Ok(read) => read,
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => return ReadStep::WouldBlock,
            Err(e) => {
                // Stop this drain; readiness re-arms and the next datagram
                // announces itself.
                log::error!("mex: recv error: {e}");
                return ReadStep::WouldBlock;
            }
        };
        let raw = self.buf[..len].to_vec();
        let ifindex = info.if_index as u32;
        if !self.ifnames.contains_key(&ifindex) || !self.subnets.contains_key(&ifindex) {
            // Stale maps (interface appeared mid-window) or an index
            // if-addrs never reports: re-query once instead of waiting
            // out the 10s refresh.
            backfill_link(
                ifindex,
                &mut self.ifnames,
                &mut self.subnets,
                &mut self.unknown,
                &link_maps,
            );
        }
        // RFC 6762 §11: multicast-destination packets are local
        // regardless of source; unicast-destination ones must come from
        // a local subnet, else silently discard (this is the spoof guard
        // for our QU unicast replies).
        if !mdns_multicast_dest(&info.addr_dst)
            && !source_on_link(&self.subnets, ifindex, &info.addr_src.ip())
        {
            self.drops.note(info.addr_src);
            return ReadStep::Handled;
        }
        let iface = self.ifnames.get(&ifindex).map(String::as_str).unwrap_or("");
        // Explicit selection drops off-selection ingress, including
        // unicast replies that bypass multicast group membership.
        if !interface_selected(iface, self.selection.as_ref()) {
            return ReadStep::Handled;
        }
        match parse_packet(&raw, info.addr_src, info.addr_dst, iface, ifindex) {
            Some(ev) => {
                if self.tx.send(ev).is_err() {
                    return ReadStep::Closed;
                }
            }
            None => self.drops.note_malformed(info.addr_src),
        }
        ReadStep::Handled
    }
}

/// One copy of the query per usable link, each forced out its own link:
/// without the per-packet interface the kernel sends everything via the
/// default multicast interface and other links (e.g. a bridge) never see
/// our queries. No usable link means no copy (`send_targets`).
fn send_on_all_interfaces(
    socket: &impl QuerySocket,
    req: &QueryRequest,
    family: Family,
    ifaces_v4: &[(String, Ipv4Addr)],
    ifaces_v6: &[(String, u32)],
    failures: &mut SendFailures,
) {
    let family_label = family.label();
    for target in send_targets(family, ifaces_v4, ifaces_v6) {
        let SendTarget { link, dest, egress } = target;
        // The egress pin is socket-wide: set it right before this copy.
        // A failed pin would send the copy out of the default multicast
        // interface instead: skip it.
        if let Err(e) = socket.pin(egress) {
            if failures
                .record_failure(family, link, SendOp::Pin, e.kind())
                .is_some()
            {
                log::error!("mex: {family_label} egress pin on {link} failed: {e}; copy skipped");
            }
            continue;
        }
        let Some(sent) = send_query(socket, req, dest, link) else {
            continue;
        };
        match sent {
            Ok(()) => {
                if failures.record_success(family, link).is_some() {
                    log::info!("mex: {family_label} send on {link} recovered");
                }
            }
            Err(e) => {
                if failures
                    .record_failure(family, link, SendOp::Send, e.kind())
                    .is_some()
                {
                    log::error!("mex: {family_label} send on {link} to {dest} failed: {e}");
                }
            }
        }
    }
}

/// Known answers relevant to one egress interface: suppression only
/// helps if a responder on *that* link holds the record, so answers
/// learned elsewhere are left out (empty origin means unknown, sent
/// everywhere; an empty egress means an unknown link, keep everything).
fn known_answers_for_iface<'a>(kas: &'a [KnownAnswer], iface: &str) -> Vec<(&'a str, u32)> {
    kas.iter()
        .filter(|ka| ka.iface.is_empty() || iface.is_empty() || ka.iface == iface)
        .map(|ka| (ka.target.as_str(), ka.ttl))
        .collect()
}

/// Split an unescaped display name into wire labels. Records are stored
/// unescaped for display, so a dot inside a DNS-SD instance label
/// (RFC 6763 §4.1.1 allows arbitrary text) is indistinguishable from a
/// separator: everything left of the LAST `<_service>._tcp|_udp` is one
/// instance label. Last-match matters: an instance label containing
/// `._tcp.`-like text (e.g. `foo._tcp.bar._http._tcp.local`) still
/// resolves to the real service suffix. Subtype owners
/// (`<sub>._sub.<_service>…`), service types, and host names split on
/// every dot.
///
/// Limits: a host or service name that itself ends in a
/// `<_service>._tcp|_udp`-shaped suffix (e.g. a host literally named
/// `x._tcp.example.com`) would split at the wrong label — but such
/// names never appear as query owners in this browser (queries are only
/// built for live interests), and re-encoding still yields a valid
/// name, just not the intended split.
fn split_instance_labels(name: &str) -> Vec<&str> {
    let name = name.trim_end_matches('.');
    let parts: Vec<&str> = name.split('.').collect();
    let Some(proto) = parts.iter().rposition(|l| is_proto_label(l.as_bytes())) else {
        return parts;
    };
    if proto < 2 || !parts[proto - 1].starts_with('_') || is_sub_label(parts[proto - 2].as_bytes())
    {
        return parts;
    }
    let service = proto - 1;
    let instance_len = parts[..service].iter().map(|l| l.len() + 1).sum::<usize>() - 1;
    let mut labels = vec![&name[..instance_len]];
    labels.extend_from_slice(&parts[service..]);
    labels
}

/// Wire name for an unescaped display name. Labels go in as raw bytes,
/// so instance names with spaces and punctuation (which presentation
/// parsers reject) encode fine. `None` means the name cannot go on the
/// wire (empty or over-long label).
fn wire_name(name: &str) -> Option<simple_dns::Name<'_>> {
    let parts = split_instance_labels(name);
    if parts.is_empty() {
        return None;
    }
    let mut labels = Vec::with_capacity(parts.len());
    for part in parts {
        let bytes = part.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        labels.push(simple_dns::Label::new_unchecked(bytes));
    }
    Some(simple_dns::Name::new_with_labels(&labels))
}

/// Largest UDP payload we will emit (RFC 6762 §17: packets MUST NOT
/// exceed 9000 bytes including IP+UDP headers; the 40-byte IPv6 header
/// is the roomier deduction).
const MAX_QUERY_BYTES: usize = 9000 - 40 - 8;

/// Encode one query for an egress interface. `None` means the owner name
/// cannot go on the wire (empty or over-long label); that is logged
/// because the scheduler has already counted the query as sent.
///
/// Names compress against byte-identical repeats (differing-case names
/// are written in full, so wire case is preserved), which keeps dense
/// known-answer lists small. If the packet still exceeds
/// `MAX_QUERY_BYTES`, known answers are shed — never the question — and
/// the cut is logged: a short refresh still elicits answers, while a
/// dropped one would lose the refresh silently (EMSGSIZE on send, past
/// the 65507-byte kernel limit). Full multipacket known-answer
/// suppression (RFC 6762 §7.2, TC-bit follow-ups) is future work.
fn encode_query(req: &QueryRequest, egress_iface: &str) -> Option<Vec<u8>> {
    let qname = match wire_name(&req.name) {
        Some(n) => n,
        None => {
            log::warn!(
                "mex: cannot encode {:?} query name {:?}",
                u16::from(req.record_type),
                req.name
            );
            return None;
        }
    };
    let mut kas = Vec::with_capacity(req.known_answers.len());
    for (ka_target, ka_ttl) in known_answers_for_iface(&req.known_answers, egress_iface) {
        let Some(rdata) = wire_name(ka_target) else {
            log::warn!(
                "mex: cannot encode known answer {ka_target:?} for {}",
                req.name
            );
            continue;
        };
        kas.push((rdata, ka_ttl));
    }

    let mut bytes = build_query(&qname, req.record_type, req.qu, &kas)?;
    if bytes.len() > MAX_QUERY_BYTES {
        let total = kas.len();
        let mut n = total;
        while n > 0 {
            n /= 2;
            kas.truncate(n);
            bytes = build_query(&qname, req.record_type, req.qu, &kas)?;
            if bytes.len() <= MAX_QUERY_BYTES {
                break;
            }
        }
        log::warn!(
            "mex: truncated known answers for {} to {} of {total} ({} bytes)",
            req.name,
            kas.len(),
            bytes.len()
        );
    }
    Some(bytes)
}

/// One query packet: question plus the given known answers, names
/// compressed. `None` only on codec failure (logged by the caller).
fn build_query(
    qname: &simple_dns::Name<'_>,
    record_type: TYPE,
    qu: bool,
    kas: &[(simple_dns::Name<'_>, u32)],
) -> Option<Vec<u8>> {
    let mut pkt = Packet::new_query(0);
    pkt.questions.push(simple_dns::Question::new(
        qname.clone(),
        QTYPE::TYPE(record_type),
        QCLASS::CLASS(CLASS::IN),
        qu,
    ));
    for (rdata, ttl) in kas {
        pkt.answers.push(ResourceRecord::new(
            qname.clone(),
            CLASS::IN,
            *ttl,
            RData::PTR(rdata.clone().into()),
        ));
    }
    match pkt.build_bytes_vec_compressed() {
        Ok(bytes) => Some(bytes),
        Err(e) => {
            log::warn!("mex: cannot encode query for {qname}: {e}");
            None
        }
    }
}

pub(crate) fn inferred_question_packet(name: &str, rtype: u16, qu: bool) -> Option<Vec<u8>> {
    let qname = wire_name(name)?;
    let record_type = record_type_from_u16(rtype)?;
    build_query(&qname, record_type, qu, &[])
}

/// Encode and send one query copy. `None` when encoding failed (already
/// logged in `encode_query`), so nothing was sent.
fn send_query(
    socket: &impl QuerySocket,
    req: &QueryRequest,
    dest: SocketAddr,
    egress_iface: &str,
) -> Option<std::io::Result<()>> {
    let bytes = encode_query(req, egress_iface)?;
    Some(socket.send_to(&bytes, dest))
}

pub(crate) fn parse_packet(
    raw: &[u8],
    source: SocketAddr,
    dst: std::net::IpAddr,
    iface: &str,
    ifindex: u32,
) -> Option<Event> {
    // Walk the record headers first: out-of-scope records are made
    // opaque before `Packet::parse`, so their rdata is never decoded and
    // a malformed one cannot fail the whole packet.
    // A packet the walk can't follow is dropped: parsing the raw bytes
    // instead would decode out-of-scope rdata after all.
    let (parse_bytes, mut wire) = walk_records(raw)?;
    let pkt = Packet::parse(&parse_bytes).ok()?;
    // `Packet::parse` moves the first OPT pseudo-record out of the
    // Additional section into the header; drop its walked entry too, so
    // walked and parsed records stay aligned.
    if let Some(i) = wire.additional.iter().position(|w| w.rtype == OPT_TYPE) {
        wire.additional.remove(i);
    }
    let dst_is_multicast = mdns_multicast_dest(&dst);
    let is_response = pkt.has_flags(PacketFlag::RESPONSE);
    let ing = Ingress {
        source,
        iface,
        ifindex,
        dst_is_multicast,
    };

    let mut answers = Vec::new();

    // Only responses carry authoritative answers. Queries may carry the
    // same answers as known answers (RFC 6762 §7.1 suppression), which
    // are beliefs, not facts: the querier (e.g. another browser on the
    // link; multicast loop is disabled so never ourselves) is not their
    // source. Filing them would conjure phantom sightings on links the
    // device never touched.
    if is_response {
        for (section, records, walked) in [
            (RecordSection::Answer, &pkt.answers, &wire.answer),
            (RecordSection::Authority, &pkt.name_servers, &wire.authority),
            (
                RecordSection::Additional,
                &pkt.additional_records,
                &wire.additional,
            ),
        ] {
            for (i, rec) in records.iter().enumerate() {
                let w = walked.get(i).copied();
                if is_opt(rec, w) {
                    continue;
                }
                answers.push(record_row(rec, w, section, ing));
            }
        }
    }

    // Known answers in queries are parsed separately for duplicate
    // question suppression (§7.3) and never filed as answers.
    let mut query_kas = Vec::new();
    if !is_response {
        for (i, rec) in pkt.answers.iter().enumerate() {
            let w = wire.answer.get(i).copied();
            if is_opt(rec, w) {
                continue;
            }
            query_kas.push(record_row(rec, w, RecordSection::KnownAnswer, ing));
        }
    }

    let mut questions = Vec::new();
    // RFC 6762 §6: responses MUST NOT carry questions, and received
    // ones MUST be silently ignored — never filed as observed queries.
    if !is_response {
        for q in &pkt.questions {
            questions.push(question_row(q, ing));
        }
    }

    Some(Event {
        answers,
        questions,
        query_kas,
        rcode: is_response.then(|| raw.get(3).copied().unwrap_or_default() & 0x0f),
        received_at: Instant::now(),
        raw_bytes: raw.to_vec(),
        source,
    })
}

/// Per-packet ingress context threaded into every row so the three
/// record/question pushes share one construction path.
#[derive(Clone, Copy)]
struct Ingress<'a> {
    source: SocketAddr,
    iface: &'a str,
    ifindex: u32,
    dst_is_multicast: bool,
}

/// One parsed resource record. Out-of-scope types
/// (`anomalies::is_mdns_answer_type` false) are never decoded: they keep
/// owner, type, class bits, TTL and their RDLENGTH (`rdlength=<n>`),
/// with no rdata bytes, so nothing downstream holds or interprets data
/// mex does not support.
fn record_row(
    rec: &ResourceRecord<'_>,
    wire_record: Option<WireRecord>,
    section: RecordSection,
    ing: Ingress<'_>,
) -> RawRecord {
    // The walked type is authoritative: out-of-scope records reach the
    // parser under `OPAQUE_TYPE`.
    let rtype = wire_record.map_or_else(|| u16::from(rec.rdata.type_code()), |w| w.rtype);
    let rdlength = wire_record.map(|w| w.rdlength);
    let in_scope = crate::anomalies::is_mdns_answer_type(rtype);
    // Known answers never reach the hex pane, so they skip the encode.
    let wire = if in_scope && section != RecordSection::KnownAnswer {
        record_wire(rec)
    } else {
        Vec::new()
    };
    let (rdata, rdata_invalid_utf8) = if in_scope {
        (rdata_label(&rec.rdata), rdata_has_invalid_utf8(&rec.rdata))
    } else {
        // `None` only if the packet walk failed, which a packet
        // `Packet::parse` accepted never does.
        let label = rdlength.map_or_else(|| "rdlength=?".to_string(), |n| format!("rdlength={n}"));
        (label, false)
    };
    RawRecord {
        name: display_name(&rec.name),
        owner_labels: rec
            .name
            .get_labels()
            .iter()
            .map(|label| label.as_ref().to_vec())
            .collect(),
        ptr_target_labels: match &rec.rdata {
            RData::PTR(target) => Some(
                target
                    .get_labels()
                    .iter()
                    .map(|label| label.as_ref().to_vec())
                    .collect(),
            ),
            _ => None,
        },
        rtype,
        rtype_str: rtype_label(rtype),
        // simple-dns exposes the top CLASS bit natively as
        // `cache_flush` (RFC 6762 §10.2).
        flush_bit: rec.cache_flush,
        qu: false,
        invalid_utf8: name_has_invalid_utf8(&rec.name) || rdata_invalid_utf8,
        ttl: rec.ttl,
        rdata,
        wire,
        source: ing.source,
        iface: ing.iface.to_string(),
        ifindex: ing.ifindex,
        dst_is_multicast: ing.dst_is_multicast,
        section,
        received_at: Instant::now(),
        trigger: None,
    }
}

fn question_row(q: &Question<'_>, ing: Ingress<'_>) -> RawRecord {
    let rtype = u16::from(q.qtype);
    RawRecord {
        name: display_name(&q.qname),
        owner_labels: q
            .qname
            .get_labels()
            .iter()
            .map(|label| label.as_ref().to_vec())
            .collect(),
        ptr_target_labels: None,
        rtype,
        rtype_str: rtype_label(rtype),
        flush_bit: false,
        qu: q.unicast_response,
        invalid_utf8: name_has_invalid_utf8(&q.qname),
        ttl: 0,
        rdata: String::new(),
        wire: Vec::new(),
        source: ing.source,
        iface: ing.iface.to_string(),
        ifindex: ing.ifindex,
        dst_is_multicast: ing.dst_is_multicast,
        section: RecordSection::Question,
        received_at: Instant::now(),
        trigger: None,
    }
}

/// Standalone wire encoding of one record for the hex pane. simple-dns
/// only serializes whole packets, so the record is wrapped in a minimal
/// reply and the 12-byte header is stripped. This deliberately uses the
/// uncompressed builder (`build_bytes_vec`, never `*_compressed`), so
/// names are written expanded with no compression pointers — matching
/// the old per-record encoding and keeping the slice self-contained.
fn record_wire(rec: &ResourceRecord<'_>) -> Vec<u8> {
    let mut pkt = Packet::new_reply(0);
    pkt.answers.push(rec.clone());
    match pkt.build_bytes_vec() {
        Ok(bytes) => bytes.get(12..).unwrap_or_default().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Type and RDLENGTH of one resource record, read from the packet
/// header fields (never from parsed rdata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct WireRecord {
    rtype: u16,
    rdlength: u16,
}

/// EDNS0 OPT pseudo-record (RFC 6891): carries options such as Apple's
/// Owner option, not data about any name, so it is never a row or a
/// sighting.
const OPT_TYPE: u16 = 41;

/// Private-use type (RFC 6895 §3.1) that out-of-scope records are
/// relabelled to before parsing, so the parser keeps their rdata as
/// opaque bytes instead of decoding it.
const OPAQUE_TYPE: u16 = 65280;

/// Whether a parsed record is the OPT pseudo-record.
fn is_opt(rec: &ResourceRecord<'_>, wire: Option<WireRecord>) -> bool {
    wire.map_or_else(|| u16::from(rec.rdata.type_code()), |w| w.rtype) == OPT_TYPE
}

/// Walked record headers per section, in wire order.
#[derive(Debug, Default, PartialEq, Eq)]
struct WalkedSections {
    answer: Vec<WireRecord>,
    authority: Vec<WireRecord>,
    additional: Vec<WireRecord>,
}

/// Walk every resource record header in a packet (answer, authority,
/// additional; questions skipped) and return a copy whose out-of-scope
/// records (`anomalies::is_mdns_answer_type` false, OPT excepted) carry
/// `OPAQUE_TYPE`, plus each record's on-wire type and RDLENGTH per
/// section. Only the TYPE field changes, so names, offsets and
/// compression pointers stay valid; re-encoding would expand
/// compressed names and misreport RDLENGTH. Every parse of received
/// bytes goes through this copy, so out-of-scope rdata is never
/// decoded. `None` when the walk falls off the end (a truncated or
/// malformed packet).
fn walk_records(raw: &[u8]) -> Option<(Vec<u8>, WalkedSections)> {
    let count = |at: usize| -> Option<usize> {
        let b = raw.get(at..at + 2)?;
        Some(usize::from(u16::from_be_bytes([b[0], b[1]])))
    };
    let questions = count(4)?;
    let (answers, authority) = (count(6)?, count(8)?);
    let records = answers + authority + count(10)?;
    let mut offset = 12;
    for _ in 0..questions {
        offset = packet_name_end(raw, offset)?.checked_add(4)?;
    }
    let mut bytes = raw.to_vec();
    let mut out = WalkedSections::default();
    for index in 0..records {
        let type_at = packet_name_end(raw, offset)?;
        let t = raw.get(type_at..type_at.checked_add(2)?)?;
        let rtype = u16::from_be_bytes([t[0], t[1]]);
        let length_at = type_at.checked_add(8)?;
        let b = raw.get(length_at..length_at.checked_add(2)?)?;
        let rdlength = u16::from_be_bytes([b[0], b[1]]);
        offset = length_at + 2 + usize::from(rdlength);
        if offset > raw.len() {
            return None;
        }
        if rtype != OPT_TYPE && !crate::anomalies::is_mdns_answer_type(rtype) {
            bytes[type_at..type_at + 2].copy_from_slice(&OPAQUE_TYPE.to_be_bytes());
        }
        let section = if index < answers {
            &mut out.answer
        } else if index < answers + authority {
            &mut out.authority
        } else {
            &mut out.additional
        };
        section.push(WireRecord { rtype, rdlength });
    }
    Some((bytes, out))
}

pub fn record_fields(wire: &[u8], rtype: u16) -> Vec<RecordField> {
    let Some(owner_end) = wire_name_end(wire, 0) else {
        return whole_record_field(wire);
    };
    let Some(type_end) = owner_end.checked_add(2) else {
        return whole_record_field(wire);
    };
    let Some(class_end) = type_end.checked_add(2) else {
        return whole_record_field(wire);
    };
    let Some(ttl_end) = class_end.checked_add(4) else {
        return whole_record_field(wire);
    };
    let Some(length_end) = ttl_end.checked_add(2) else {
        return whole_record_field(wire);
    };
    let Some(header) = wire.get(owner_end..length_end) else {
        return whole_record_field(wire);
    };
    let rdata_len = u16::from_be_bytes([header[8], header[9]]) as usize;
    let rdata_end = length_end.saturating_add(rdata_len);
    if rdata_end != wire.len() {
        return whole_record_field(wire);
    }

    let mut fields = vec![
        record_field("Owner name", 0, owner_end),
        record_field("Record type", owner_end, type_end),
        record_field("Class / cache-flush", type_end, class_end),
        record_field("TTL", class_end, ttl_end),
        record_field("RDATA length", ttl_end, length_end),
        record_field("RDATA", length_end, rdata_end),
    ];

    let data_fields = match rtype {
        1 if rdata_len == 4 => vec![record_field("IPv4 address", length_end, rdata_end)],
        28 if rdata_len == 16 => vec![record_field("IPv6 address", length_end, rdata_end)],
        2 | 5 | 12 => wire_name_end(wire, length_end)
            .filter(|end| *end == rdata_end)
            .map(|end| {
                let label = match rtype {
                    2 => "Name server",
                    5 => "Canonical name",
                    _ => "PTR target",
                };
                vec![record_field(label, length_end, end)]
            })
            .unwrap_or_default(),
        33 if rdata_len >= 7 => {
            let target_start = length_end + 6;
            wire_name_end(wire, target_start)
                .filter(|end| *end == rdata_end)
                .map(|end| {
                    vec![
                        record_field("Priority", length_end, length_end + 2),
                        record_field("Weight", length_end + 2, length_end + 4),
                        record_field("Port", length_end + 4, target_start),
                        record_field("Target", target_start, end),
                    ]
                })
                .unwrap_or_default()
        }
        16 => txt_string_fields(wire, length_end, rdata_end),
        _ => Vec::new(),
    };
    fields.extend(data_fields);
    fields
}

pub fn question_fields(wire: &[u8], name: &str, rtype_str: &str) -> Option<Vec<RecordField>> {
    // Parse the opaque copy: known answers in the stored query must not
    // be decoded (or fail the parse) when they are out of scope. The
    // layout is identical, so field offsets apply to `wire`.
    let (opaque, _) = walk_records(wire)?;
    let packet = Packet::parse(&opaque).ok()?;
    if packet.has_flags(PacketFlag::RESPONSE) {
        return None;
    }
    let question_count = u16::from_be_bytes(wire.get(4..6)?.try_into().ok()?) as usize;
    if question_count != packet.questions.len() {
        return None;
    }

    let mut selected_index = None;
    for (index, question) in packet.questions.iter().enumerate() {
        if display_name(&question.qname).trim_end_matches('.') == name.trim_end_matches('.')
            && rtype_label(u16::from(question.qtype)) == rtype_str
            && selected_index.replace(index).is_some()
        {
            return None;
        }
    }
    let selected_index = selected_index?;

    let mut offset = 12;
    for (index, _) in packet.questions.iter().enumerate() {
        let name_end = packet_name_end(wire, offset)?;
        let type_end = name_end.checked_add(2)?;
        let class_end = type_end.checked_add(2)?;
        wire.get(offset..class_end)?;
        if index == selected_index {
            return Some(vec![
                record_field("QNAME", offset, name_end),
                record_field("QTYPE", name_end, type_end),
                record_field("QCLASS / QU", type_end, class_end),
            ]);
        }
        offset = class_end;
    }
    None
}

fn record_field(label: &str, start: usize, end: usize) -> RecordField {
    RecordField {
        label: label.to_string(),
        start,
        end,
    }
}

fn whole_record_field(wire: &[u8]) -> Vec<RecordField> {
    if wire.is_empty() {
        Vec::new()
    } else {
        vec![record_field("Record", 0, wire.len())]
    }
}

/// RDLENGTH of a standalone record wire encoding (uncompressed owner,
/// type, class, TTL, RDLENGTH, RDATA): the exact on-wire RDATA size.
/// `None` when the encoding is missing or truncated.
pub(crate) fn wire_rdata_len(wire: &[u8]) -> Option<usize> {
    let rdlen_at = wire_name_end(wire, 0)?.checked_add(8)?;
    let rdlen = wire.get(rdlen_at..rdlen_at.checked_add(2)?)?;
    Some(usize::from(u16::from_be_bytes([rdlen[0], rdlen[1]])))
}

fn wire_name_end(wire: &[u8], start: usize) -> Option<usize> {
    wire_name_end_with_pointers(wire, start, false)
}

fn packet_name_end(wire: &[u8], start: usize) -> Option<usize> {
    wire_name_end_with_pointers(wire, start, true)
}

fn wire_name_end_with_pointers(
    wire: &[u8],
    start: usize,
    allow_compression_pointers: bool,
) -> Option<usize> {
    let mut offset = start;
    loop {
        let length = *wire.get(offset)?;
        match length & 0xc0 {
            0 => {
                offset = offset.checked_add(1)?;
                if length == 0 {
                    return Some(offset);
                }
                offset = offset.checked_add(length as usize)?;
                wire.get(start..offset)?;
            }
            0xc0 if allow_compression_pointers => {
                let pointer_end = offset.checked_add(2)?;
                let pointer = wire.get(offset..pointer_end)?;
                let target = (usize::from(pointer[0] & 0x3f) << 8) | usize::from(pointer[1]);
                if target >= offset || target >= wire.len() {
                    return None;
                }
                return Some(pointer_end);
            }
            _ => return None,
        }
    }
}

fn txt_string_fields(wire: &[u8], start: usize, end: usize) -> Vec<RecordField> {
    let mut fields = Vec::new();
    let mut offset = start;
    while offset < end {
        let Some(length) = wire.get(offset).copied().map(usize::from) else {
            return Vec::new();
        };
        let string_end = offset.saturating_add(1).saturating_add(length);
        if string_end > end {
            return Vec::new();
        }
        fields.push(record_field(
            &format!("TXT string {}", fields.len() + 1),
            offset,
            string_end,
        ));
        offset = string_end;
    }
    fields
}

/// The record types this browser maintains interest in (RFC 6762 §5.2:
/// no queries without active interest). Single source of truth for the
/// u16 wire code → query type mapping; the scheduler and the refresh
/// pass share it. Kept separate from `rtype_label` on purpose: the label
/// map must stay keyed by raw u16 because it also renders QTYPE-only
/// codes such as ANY (255), which have no `TYPE` counterpart.
pub fn record_type_from_u16(rtype: u16) -> Option<TYPE> {
    match rtype {
        12 => Some(TYPE::PTR),
        33 => Some(TYPE::SRV),
        16 => Some(TYPE::TXT),
        1 => Some(TYPE::A),
        28 => Some(TYPE::AAAA),
        _ => None,
    }
}

/// Whether a label is a DNS-SD protocol label, `_tcp` or `_udp`
/// (RFC 6763 §7), ignoring case.
pub(crate) fn is_proto_label(label: &[u8]) -> bool {
    label.eq_ignore_ascii_case(b"_tcp") || label.eq_ignore_ascii_case(b"_udp")
}

/// Whether a label is the DNS-SD subtype keyword `_sub` (RFC 6763
/// §7.1), ignoring case.
pub(crate) fn is_sub_label(label: &[u8]) -> bool {
    label.eq_ignore_ascii_case(b"_sub")
}

/// Byte offset of a case-insensitive `.local` suffix in a dot-trimmed
/// name. Byte-wise compare: a match on the ASCII suffix also proves the
/// offset is a char boundary, so slicing there cannot panic.
fn local_suffix_offset(trimmed: &str) -> Option<usize> {
    let off = trimmed.len().checked_sub(".local".len())?;
    trimmed.as_bytes()[off..]
        .eq_ignore_ascii_case(b".local")
        .then_some(off)
}

/// `name` without trailing root dots and its `.local` suffix
/// (`printer.local.` → `printer`), matched case-insensitively. `None`
/// when the name is not under `.local` or nothing precedes the suffix.
pub(crate) fn strip_local_suffix(name: &str) -> Option<&str> {
    let trimmed = name.trim_end_matches('.');
    local_suffix_offset(trimmed)
        .filter(|&off| off > 0)
        .map(|off| &trimmed[..off])
}

/// Whether `name` is `local` itself or ends in `.local` (RFC 6762 §3),
/// ignoring case and trailing root dots.
pub(crate) fn is_local_name(name: &str) -> bool {
    let trimmed = name.trim_end_matches('.');
    trimmed.eq_ignore_ascii_case("local") || local_suffix_offset(trimmed).is_some()
}

/// Mnemonics for the in-scope record/question types
/// (`anomalies::is_mdns_answer_type` / `is_mdns_question_type`),
/// including QTYPE-only codes such as ANY (255) that have no `TYPE`
/// counterpart — which is why this stays keyed by raw u16 instead of
/// the query-type enum. Every other type renders as RFC 3597 `TYPEnn`,
/// so mex never names a type it does not support. Single source for
/// both directions of the mapping.
const RTYPE_NAMES: &[(u16, &str)] = &[
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (12, "PTR"),
    (13, "HINFO"),
    (16, "TXT"),
    (28, "AAAA"),
    (33, "SRV"),
    (47, "NSEC"),
    (255, "ANY"),
];

/// Mnemonic for a numeric type, if it has one in `RTYPE_NAMES`.
pub(crate) fn rtype_name(rtype: u16) -> Option<&'static str> {
    RTYPE_NAMES
        .iter()
        .find_map(|&(code, name)| (code == rtype).then_some(name))
}

/// Human label for a numeric record/question type: its mnemonic, or the
/// RFC 3597 `TYPEnn` form for anything else.
pub(crate) fn rtype_label(rtype: u16) -> String {
    rtype_name(rtype).map_or_else(|| format!("TYPE{rtype}"), str::to_string)
}

/// Address types (A, AAAA) named in an NSEC row's rendered bitmap
/// (`next_name TYPE…`), and whether it names any other type. Shared by
/// address denials (app) and the inverted-bitmap finding (analyzer), so
/// both read the same rule.
pub(crate) fn nsec_address_types(rdata: &str) -> (Vec<u16>, bool) {
    let mut address = Vec::new();
    let mut other = false;
    for t in rdata.split_whitespace().skip(1).filter_map(rtype_from_str) {
        match t {
            1 | 28 => address.push(t),
            _ => other = true,
        }
    }
    (address, other)
}

/// Numeric type for a displayed label (`A` → 1, …, `TYPE47` → 47); the
/// inverse of `rtype_label`. `None` means unrecognised: callers stay
/// quiet rather than guessing.
pub(crate) fn rtype_from_str(s: &str) -> Option<u16> {
    RTYPE_NAMES
        .iter()
        .find_map(|&(code, name)| (name == s).then_some(code))
        .or_else(|| s.strip_prefix("TYPE").and_then(|n| n.parse().ok()))
}

fn rdata_label(data: &RData) -> String {
    match data {
        RData::A(a) => Ipv4Addr::from(a.address).to_string(),
        RData::AAAA(a) => Ipv6Addr::from(a.address).to_string(),
        RData::SRV(srv) => {
            format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                display_name(&srv.target)
            )
        }
        RData::TXT(txt) => txt
            .iter_raw()
            .map(|(k, v)| {
                let key = String::from_utf8_lossy(k).into_owned();
                match v {
                    Some(val) => format!("{key}={}", String::from_utf8_lossy(val)),
                    None => key,
                }
            })
            .collect::<Vec<_>>()
            .join("; "),
        RData::PTR(n) => display_name(n),
        RData::CNAME(n) => display_name(n),
        RData::NS(n) => display_name(n),
        RData::HINFO(h) => {
            format!("{} {}", h.cpu, h.os)
        }
        RData::NSEC(nsec) => {
            let types = nsec
                .types()
                .map(|t| rtype_label(t.into()))
                .collect::<Vec<_>>();
            let name = display_name(&nsec.next_name);
            if types.is_empty() {
                name
            } else {
                format!("{name} {}", types.join(" "))
            }
        }
        _ => String::new(),
    }
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
    fn multicast_loop_is_disabled() {
        // Querier-only: own transmissions must not loop back and be
        // re-ingested. Failure here is loud (startup errors propagate).
        let std4 = create_v4_socket().unwrap().try_clone_std().unwrap();
        assert!(!socket2::Socket::from(std4).multicast_loop_v4().unwrap());
        let std6 = create_v6_socket().unwrap().try_clone_std().unwrap();
        assert!(!socket2::Socket::from(std6).multicast_loop_v6().unwrap());
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
            send_on_all_interfaces(&socket, &ptr_query(), family, &[], &[], &mut failures);
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
