use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
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
/// never become refresh query names).
fn rdata_has_invalid_utf8(rdata: &RData) -> bool {
    // Each name-wrapper is its own type, so the arms cannot share one
    // binding; every arm just asks the same question of its names.
    match rdata {
        RData::PTR(n) => name_has_invalid_utf8(n),
        RData::CNAME(n) => name_has_invalid_utf8(n),
        RData::NS(n) => name_has_invalid_utf8(n),
        RData::MD(n) => name_has_invalid_utf8(n),
        RData::MF(n) => name_has_invalid_utf8(n),
        RData::MB(n) => name_has_invalid_utf8(n),
        RData::MG(n) => name_has_invalid_utf8(n),
        RData::MR(n) => name_has_invalid_utf8(n),
        RData::NSAP_PTR(n) => name_has_invalid_utf8(n),
        RData::MX(mx) => name_has_invalid_utf8(&mx.exchange),
        RData::SOA(soa) => name_has_invalid_utf8(&soa.mname) || name_has_invalid_utf8(&soa.rname),
        RData::SRV(srv) => name_has_invalid_utf8(&srv.target),
        RData::SVCB(svcb) => name_has_invalid_utf8(&svcb.target),
        RData::HTTPS(svcb) => name_has_invalid_utf8(&svcb.target),
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
/// How often the listener threads re-enumerate interfaces: picks up
/// bridges and other links that appear at runtime, drops dead ones from
/// the transmit set, and re-joins flapped ones (replug or down/up with
/// the same name would otherwise stay deaf: the kernel join does not
/// survive the interface going away).
const IFACE_REFRESH: Duration = Duration::from_secs(10);

/// Address family of a listener thread: selects the interface list,
/// the join call, and the per-packet transmit interface.
#[derive(Clone, Copy)]
enum Family {
    V4,
    V6,
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

#[derive(Debug, Clone)]
pub struct RawRecord {
    pub name: String,
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
    /// False means a unicast reply (QU response or legacy unicast), which
    /// the analyzer treats as unconfirmed context for leak/flush verdicts.
    pub dst_is_multicast: bool,
    /// Which DNS section carried the record. Responses merge answer /
    /// authority / additional sections; known answers ride in queries.
    pub section: RecordSection,
    pub received_at: Instant,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub answers: Vec<RawRecord>,
    pub questions: Vec<RawRecord>,
    /// Known answers carried in query packets (RFC 6762 §7.1). Never filed
    /// as sightings (queries are beliefs, not facts); used only for
    /// duplicate question suppression (§7.3) subset checks.
    pub query_kas: Vec<RawRecord>,
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

/// Query sender fanning out to both transports, so solicited queries
/// reach v6-only responders too. A dead listener thread just drops its copy.
pub struct QueryTx {
    v4: mpsc::Sender<QueryRequest>,
    v6: mpsc::Sender<QueryRequest>,
}

impl QueryTx {
    /// Fan out to both transports. Returns `true` when at least one
    /// listener channel accepted the request — the transport may still
    /// fail to send (encode error, closed socket), which is logged in
    /// `send_query` and cannot be reflected here.
    pub fn send(&self, req: QueryRequest) -> bool {
        let v4_ok = self.v4.send(req.clone()).is_ok();
        let v6_ok = self.v6.send(req).is_ok();
        v4_ok || v6_ok
    }
}

/// Refused-packet accounting shared with the App thread: RFC 6762 §11
/// off-link discards plus messages the DNS codec cannot decode at all.
/// Listener threads only bump these; rendering reads them.
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
    let (tx_v4, rx_v4) = mpsc::channel();
    let (tx_v6, rx_v6) = mpsc::channel();
    let drops = Arc::new(DropStats::default());

    let tx4 = tx.clone();
    let drops4 = drops.clone();
    let sel4 = selection.clone();
    thread::spawn(move || {
        let socket = match create_v4_socket() {
            Ok(s) => s,
            Err(e) => {
                log::error!("mex: v4 socket: {e}");
                return;
            }
        };
        listen(&socket, tx4, rx_v4, drops4, Family::V4, sel4);
    });

    let drops6 = drops.clone();
    thread::spawn(move || {
        let socket = match create_v6_socket() {
            Ok(s) => s,
            Err(e) => {
                log::error!("mex: v6 socket: {e}");
                return;
            }
        };
        listen(&socket, tx, rx_v6, drops6, Family::V6, selection);
    });

    Ok((
        QueryTx {
            v4: tx_v4,
            v6: tx_v6,
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

fn listen(
    socket: &PktInfoUdpSocket,
    tx: mpsc::Sender<Event>,
    query_rx: mpsc::Receiver<QueryRequest>,
    drops: Arc<DropStats>,
    family: Family,
    selection: Option<HashSet<String>>,
) {
    let mut buf = vec![0u8; 65535];
    let mut ifaces_v4: Vec<(String, Ipv4Addr)> = Vec::new();
    let mut ifaces_v6: Vec<(String, u32)> = Vec::new();
    let mut ifnames: HashMap<u32, String> = HashMap::new();
    let mut subnets: SubnetMap = HashMap::new();
    let mut unknown: HashSet<u32> = HashSet::new();
    let mut last_refresh: Option<Instant> = None;

    loop {
        if last_refresh
            .map(|t| t.elapsed() >= IFACE_REFRESH)
            .unwrap_or(true)
        {
            last_refresh = Some(Instant::now());
            log::debug!("mex: refreshing interface list");
            (ifnames, subnets) = link_maps();
            unknown.clear();
            // Joins run unconditionally every pass: they are idempotent,
            // and a rejoin is required after an interface went away and
            // came back (same name, new incarnation).
            match family {
                Family::V4 => {
                    ifaces_v4 = v4_interfaces(selection.as_ref());
                    for (name, ip) in &ifaces_v4 {
                        if let Err(e) = socket.join_multicast_v4(&MDNS_V4, ip) {
                            // Duplicate joins report AddrInUse; the membership
                            // is already in place, so only log real failures.
                            if e.kind() != std::io::ErrorKind::AddrInUse {
                                log::warn!("mex: v4 mcast {name}: {e}");
                            }
                        }
                    }
                }
                Family::V6 => {
                    ifaces_v6 = v6_interfaces(selection.as_ref());
                    for (name, idx) in &ifaces_v6 {
                        if let Err(e) = socket.join_multicast_v6(&MDNS_V6, *idx) {
                            if e.kind() != std::io::ErrorKind::AddrInUse {
                                log::warn!("mex: v6 mcast {name}: {e}");
                            }
                        }
                    }
                }
            }
        }

        // drain any pending outgoing queries
        while let Ok(req) = query_rx.try_recv() {
            send_on_all_interfaces(socket, &req, family, &ifaces_v4, &ifaces_v6);
        }

        match socket.recv(&mut buf) {
            Ok((len, info)) => {
                // The v6 socket is dual-stack (no IPV6_V6ONLY setter on the
                // wrapper): v4 traffic also arrives here as v4-mapped. Drop
                // it so the v4 socket remains the single owner of v4
                // packets instead of recording everything twice.
                if is_v4_mapped(&info.addr_src) {
                    continue;
                }
                let raw = buf[..len].to_vec();
                let ifindex = info.if_index as u32;
                if !ifnames.contains_key(&ifindex) || !subnets.contains_key(&ifindex) {
                    // Stale maps (interface appeared mid-window) or an
                    // index if-addrs never reports: re-query once
                    // instead of waiting out the 10s refresh.
                    backfill_link(
                        ifindex,
                        &mut ifnames,
                        &mut subnets,
                        &mut unknown,
                        &link_maps,
                    );
                }
                // RFC 6762 §11: multicast-destination packets are local
                // regardless of source; unicast-destination ones must
                // come from a local subnet, else silently discard (this
                // is the spoof guard for our QU unicast replies).
                if !mdns_multicast_dest(&info.addr_dst)
                    && !source_on_link(&subnets, ifindex, &info.addr_src.ip())
                {
                    drops.note(info.addr_src);
                    continue;
                }
                let iface = ifnames.get(&ifindex).map(String::as_str).unwrap_or("");
                // Explicit selection drops off-selection ingress, including
                // unicast replies that bypass multicast group membership.
                if !interface_selected(iface, selection.as_ref()) {
                    continue;
                }
                match parse_packet(&raw, info.addr_src, info.addr_dst, iface, ifindex) {
                    Some(ev) => {
                        if tx.send(ev).is_err() {
                            break;
                        }
                    }
                    None => drops.note_malformed(info.addr_src),
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                log::error!("mex: recv error: {e}");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

/// One copy of the query per local interface, each forced out its own
/// link: without the per-packet interface the kernel sends everything
/// via the default multicast interface and other links (e.g. a bridge)
/// never see our queries.
fn send_on_all_interfaces(
    socket: &PktInfoUdpSocket,
    req: &QueryRequest,
    family: Family,
    ifaces_v4: &[(String, Ipv4Addr)],
    ifaces_v6: &[(String, u32)],
) {
    match family {
        Family::V4 => {
            if ifaces_v4.is_empty() {
                let dest = SocketAddr::from(SocketAddrV4::new(MDNS_V4, MDNS_PORT));
                send_query(socket, req, dest, "");
                return;
            }
            for (name, ip) in ifaces_v4 {
                let _ = socket.set_multicast_if_v4(ip);
                let dest = SocketAddr::from(SocketAddrV4::new(MDNS_V4, MDNS_PORT));
                send_query(socket, req, dest, name);
            }
        }
        Family::V6 => {
            if ifaces_v6.is_empty() {
                send_query(socket, req, mdns_dest_v6(0), "");
                return;
            }
            for (name, idx) in ifaces_v6 {
                let _ = socket.set_multicast_if_v6(*idx);
                send_query(socket, req, mdns_dest_v6(*idx), name);
            }
        }
    }
}

fn is_v4_mapped(addr: &SocketAddr) -> bool {
    match addr.ip() {
        IpAddr::V6(v6) => v6.to_ipv4_mapped().is_some(),
        _ => false,
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
    let Some(proto) = parts
        .iter()
        .rposition(|l| l.eq_ignore_ascii_case("_tcp") || l.eq_ignore_ascii_case("_udp"))
    else {
        return parts;
    };
    if proto < 2
        || !parts[proto - 1].starts_with('_')
        || parts[proto - 2].eq_ignore_ascii_case("_sub")
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

fn send_query(socket: &PktInfoUdpSocket, req: &QueryRequest, dest: SocketAddr, egress_iface: &str) {
    let Some(bytes) = encode_query(req, egress_iface) else {
        return;
    };
    let _ = socket.send_to(&bytes, &SockAddr::from(dest));
}

fn parse_packet(
    raw: &[u8],
    source: SocketAddr,
    dst: std::net::IpAddr,
    iface: &str,
    ifindex: u32,
) -> Option<Event> {
    let pkt = Packet::parse(raw).ok()?;
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
        for (section, rec) in pkt
            .answers
            .iter()
            .map(|r| (RecordSection::Answer, r))
            .chain(
                pkt.name_servers
                    .iter()
                    .map(|r| (RecordSection::Authority, r)),
            )
            .chain(
                pkt.additional_records
                    .iter()
                    .map(|r| (RecordSection::Additional, r)),
            )
        {
            answers.push(record_row(rec, record_wire(rec), section, ing));
        }
    }

    // Known answers in queries are parsed separately for duplicate
    // question suppression (§7.3) and never filed as answers.
    let mut query_kas = Vec::new();
    if !is_response {
        for rec in pkt.answers.iter() {
            query_kas.push(record_row(rec, Vec::new(), RecordSection::KnownAnswer, ing));
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

fn record_row(
    rec: &ResourceRecord<'_>,
    wire: Vec<u8>,
    section: RecordSection,
    ing: Ingress<'_>,
) -> RawRecord {
    let rtype = u16::from(rec.rdata.type_code());
    RawRecord {
        name: display_name(&rec.name),
        rtype,
        rtype_str: rtype_label(rtype),
        // simple-dns exposes the top CLASS bit natively as
        // `cache_flush` (RFC 6762 §10.2).
        flush_bit: rec.cache_flush,
        qu: false,
        invalid_utf8: name_has_invalid_utf8(&rec.name) || rdata_has_invalid_utf8(&rec.rdata),
        ttl: rec.ttl,
        rdata: rdata_label(&rec.rdata),
        wire,
        source: ing.source,
        iface: ing.iface.to_string(),
        ifindex: ing.ifindex,
        dst_is_multicast: ing.dst_is_multicast,
        section,
        received_at: Instant::now(),
    }
}

fn question_row(q: &Question<'_>, ing: Ingress<'_>) -> RawRecord {
    let rtype = u16::from(q.qtype);
    RawRecord {
        name: display_name(&q.qname),
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

/// Human label for a numeric record/question type, including QTYPE-only
/// codes such as ANY (255) that have no `TYPE` counterpart — which is
/// why this stays keyed by raw u16 instead of the query-type enum.
pub(crate) fn rtype_label(rtype: u16) -> String {
    match rtype {
        1 => "A".into(),
        28 => "AAAA".into(),
        33 => "SRV".into(),
        16 => "TXT".into(),
        12 => "PTR".into(),
        5 => "CNAME".into(),
        2 => "NS".into(),
        47 => "NSEC".into(),
        255 => "ANY".into(),
        6 => "SOA".into(),
        15 => "MX".into(),
        _ => format!("TYPE{rtype}"),
    }
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
        RData::MD(n) => display_name(n),
        RData::MF(n) => display_name(n),
        RData::MB(n) => display_name(n),
        RData::MG(n) => display_name(n),
        RData::MR(n) => display_name(n),
        RData::NSAP_PTR(n) => display_name(n),
        RData::MX(mx) => format!("{} {}", mx.preference, display_name(&mx.exchange)),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            display_name(&soa.mname),
            display_name(&soa.rname),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        RData::HINFO(h) => {
            format!("{} {}", h.cpu, h.os)
        }
        RData::SVCB(svcb) => display_name(&svcb.target),
        RData::HTTPS(svcb) => display_name(&svcb.target),
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
