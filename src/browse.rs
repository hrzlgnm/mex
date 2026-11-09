use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{mpsc, Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use hickory_proto::op::{Message, MessageType, OpCode, Query};
use hickory_proto::rr::{Name, RData, Record, RecordType};

use hickory_proto::serialize::binary::BinDecodable;
use hickory_proto::serialize::binary::BinEncodable;

fn unescape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    let mut chars = s.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            // collect up to 3 octal digits
            let mut octal = String::with_capacity(3);
            for _ in 0..3 {
                match chars.clone().next() {
                    Some(d) if d.is_ascii_digit() && d <= '7' => {
                        octal.push(chars.next().unwrap());
                    }
                    _ => break,
                }
            }
            if !octal.is_empty() {
                if let Ok(byte) = u8::from_str_radix(&octal, 8) {
                    out.push(byte as char);
                }
            } else if let Some(next) = chars.next() {
                out.push(next);
            }
        } else {
            out.push(c);
        }
    }
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

#[derive(Debug, Clone)]
pub struct RawRecord {
    pub name: String,
    pub rtype: u16,
    pub rtype_str: String,
    pub flush_bit: bool,
    pub qu: bool,
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
    pub received_at: Instant,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub records: Vec<RawRecord>,
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
    pub record_type: RecordType,
    /// PTR target names to include as known-answer records (owner name = self.name).
    /// Each TTL must be the *remaining* TTL, and callers must omit records
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
    pub fn send(&self, req: QueryRequest) {
        let _ = self.v4.send(req.clone());
        let _ = self.v6.send(req);
    }
}

/// Refused-packet accounting shared with the App thread (RFC 6762 §11
/// off-link discards). Listener threads only bump it; rendering reads it.
#[derive(Debug, Default)]
pub struct DropStats {
    count: AtomicU64,
    last: Mutex<Option<(SocketAddr, Instant)>>,
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
}

pub fn spawn() -> Result<(QueryTx, mpsc::Receiver<Event>, Arc<DropStats>)> {
    let (tx, rx) = mpsc::channel();
    let (tx_v4, rx_v4) = mpsc::channel();
    let (tx_v6, rx_v6) = mpsc::channel();
    let drops = Arc::new(DropStats::default());

    let tx4 = tx.clone();
    let drops4 = drops.clone();
    thread::spawn(move || {
        let socket = match create_v4_socket() {
            Ok(s) => s,
            Err(e) => {
                log::error!("mex: v4 socket: {e}");
                return;
            }
        };
        listen(&socket, tx4, rx_v4, drops4, Family::V4);
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
        listen(&socket, tx, rx_v6, drops6, Family::V6);
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
    /// Distinct names skipped by policy (`lo`/`docker`/`veth`).
    pub skipped: Vec<String>,
    /// Distinct names that are down or point-to-point (no multicast).
    pub inactive: Vec<String>,
}

pub fn link_stats() -> LinkStats {
    let mut stats = LinkStats::default();
    let mut seen_v4 = HashSet::new();
    let mut seen_v6 = HashSet::new();
    let mut seen_skipped = HashSet::new();
    let mut seen_inactive = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if skipped_interface(&iface.name) {
            if seen_skipped.insert(iface.name.clone()) {
                stats.skipped.push(iface.name.clone());
            }
            continue;
        }
        if !usable_interface(&iface) {
            if seen_inactive.insert(iface.name.clone()) {
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

fn v4_interfaces() -> Vec<(String, Ipv4Addr)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if skipped_interface(&iface.name) || !usable_interface(&iface) {
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

fn v6_interfaces() -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if skipped_interface(&iface.name) || !usable_interface(&iface) {
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
            (ifnames, subnets) = link_maps();
            unknown.clear();
            // Joins run unconditionally every pass: they are idempotent,
            // and a rejoin is required after an interface went away and
            // came back (same name, new incarnation).
            match family {
                Family::V4 => {
                    ifaces_v4 = v4_interfaces();
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
                    ifaces_v6 = v6_interfaces();
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
                if let Some(ev) = parse_packet(&raw, info.addr_src, iface, ifindex) {
                    if tx.send(ev).is_err() {
                        break;
                    }
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

fn send_query(socket: &PktInfoUdpSocket, req: &QueryRequest, dest: SocketAddr, egress_iface: &str) {
    let qname = match Name::from_ascii(format!("{}.", req.name)) {
        Ok(n) => n,
        Err(_) => return,
    };
    let mut msg = Message::new(0, MessageType::Query, OpCode::Query);
    let mut query = Query::query(qname.clone(), req.record_type);
    query.set_mdns_unicast_response(req.qu);
    msg.add_query(query);

    for (ka_target, ka_ttl) in known_answers_for_iface(&req.known_answers, egress_iface) {
        let target = ka_target.trim_end_matches('.');
        if let Ok(rdata) = Name::from_ascii(format!("{target}.")) {
            let rec = Record::from_rdata(
                qname.clone(),
                ka_ttl,
                RData::PTR(hickory_proto::rr::rdata::PTR(rdata)),
            );
            msg.add_answer(rec);
        }
    }

    let bytes = match msg.to_vec() {
        Ok(b) => b,
        Err(_) => return,
    };
    let _ = socket.send_to(&bytes, &SockAddr::from(dest));
}

fn parse_packet(raw: &[u8], source: SocketAddr, iface: &str, ifindex: u32) -> Option<Event> {
    let msg = Message::from_bytes(raw).ok()?;

    let mut records = Vec::new();

    // Only responses carry authoritative records. Queries may carry the
    // same records as known answers (RFC 6762 §7.1 suppression), which
    // are beliefs, not facts: the querier (e.g. another browser on the
    // link; multicast loop is disabled so never ourselves) is not their
    // source. Filing them would conjure phantom sightings on links the
    // device never touched.
    if msg.metadata.message_type == MessageType::Response {
        for rec in msg
            .answers
            .iter()
            .chain(&msg.authorities)
            .chain(&msg.additionals)
        {
            records.push(RawRecord {
                name: unescape(&rec.name.to_string()),
                rtype: u16::from(rec.record_type()),
                rtype_str: rtype_label(rec.record_type()),
                // hickory-proto strips the top CLASS bit at decode and
                // exposes it via the mdns_cache_flush field; reading
                // dns_class directly always yields a clear bit (RFC 6762 §10.2).
                flush_bit: rec.mdns_cache_flush,
                qu: false,
                ttl: rec.ttl,
                rdata: rdata_label(&rec.data, raw),
                wire: rec.to_bytes().unwrap_or_default(),
                source,
                iface: iface.to_string(),
                ifindex,
                received_at: Instant::now(),
            });
        }
    }

    // Known answers in queries are parsed separately for duplicate
    // question suppression (§7.3) and never filed as records.
    let mut query_kas = Vec::new();
    if msg.metadata.message_type == MessageType::Query {
        for rec in msg.answers.iter() {
            query_kas.push(RawRecord {
                name: unescape(&rec.name.to_string()),
                rtype: u16::from(rec.record_type()),
                rtype_str: rtype_label(rec.record_type()),
                flush_bit: rec.mdns_cache_flush,
                qu: false,
                ttl: rec.ttl,
                rdata: rdata_label(&rec.data, raw),
                wire: Vec::new(),
                source,
                iface: iface.to_string(),
                ifindex,
                received_at: Instant::now(),
            });
        }
    }

    let mut questions = Vec::new();
    for q in &msg.queries {
        questions.push(RawRecord {
            name: unescape(&q.name().to_string()),
            rtype: u16::from(q.query_type()),
            rtype_str: rtype_label(q.query_type()),
            flush_bit: false,
            qu: q.mdns_unicast_response(),
            ttl: 0,
            rdata: String::new(),
            wire: Vec::new(),
            source,
            iface: iface.to_string(),
            ifindex,
            received_at: Instant::now(),
        });
    }

    Some(Event {
        records,
        questions,
        query_kas,
        raw_bytes: raw.to_vec(),
        source,
    })
}

fn rtype_label(rtype: RecordType) -> String {
    match rtype {
        RecordType::A => "A".into(),
        RecordType::AAAA => "AAAA".into(),
        RecordType::SRV => "SRV".into(),
        RecordType::TXT => "TXT".into(),
        RecordType::PTR => "PTR".into(),
        RecordType::CNAME => "CNAME".into(),
        RecordType::NS => "NS".into(),
        RecordType::NSEC => "NSEC".into(),
        RecordType::ANY => "ANY".into(),
        RecordType::SOA => "SOA".into(),
        RecordType::MX => "MX".into(),
        _ => format!("TYPE{}", u16::from(rtype)),
    }
}

fn rdata_label(data: &RData, msg: &[u8]) -> String {
    match data {
        RData::A(ip) => ip.to_string(),
        RData::AAAA(ip) => ip.to_string(),
        RData::SRV(srv) => {
            format!(
                "{} {} {} {}",
                srv.priority,
                srv.weight,
                srv.port,
                unescape(&srv.target.to_string())
            )
        }
        RData::TXT(txt) => txt
            .txt_data
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<Vec<_>>()
            .join("; "),
        RData::PTR(n) => unescape(&n.to_string()),
        RData::CNAME(n) => unescape(&n.to_string()),
        RData::NS(n) => unescape(&n.to_string()),
        RData::MX(mx) => format!("{} {}", mx.preference, unescape(&mx.exchange.to_string())),
        RData::SOA(soa) => format!(
            "{} {} {} {} {} {} {}",
            unescape(&soa.mname.to_string()),
            unescape(&soa.rname.to_string()),
            soa.serial,
            soa.refresh,
            soa.retry,
            soa.expire,
            soa.minimum
        ),
        RData::HINFO(h) => {
            let cpu = String::from_utf8_lossy(&h.cpu);
            let os = String::from_utf8_lossy(&h.os);
            format!("{cpu} {os}")
        }
        RData::SVCB(svcb) => unescape(&svcb.target_name.to_string()),
        RData::Unknown { code, rdata } if *code == RecordType::NSEC => {
            decode_nsec(&rdata.anything, msg)
        }
        _ => String::new(),
    }
}

/// Decode NSEC rdata (next name + type bit maps, RFC 4034 §4.1) for display:
/// "<next-name> <TYPE>...". The next name is usually inline, but may be a
/// compression pointer (or end in one) whose target lives outside rdata, so
/// the full message is passed for context and pointers are resolved against
/// it. Names that cannot be resolved render as "…".
fn decode_nsec(rdata: &[u8], msg: &[u8]) -> String {
    let mut pos = 0;
    let mut labels = Vec::new();
    let mut unresolved = false;
    // Next domain name in wire format. Inline labels are collected here; a
    // compression pointer terminates the inline part (`pos` still advances
    // past it, so the type bitmaps below are read from the right offset).
    let mut truncated = false;
    while let Some(&len) = rdata.get(pos) {
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 == 0xC0 {
            let hi = (len & 0x3F) as usize;
            let Some(&lo) = rdata.get(pos + 1) else {
                truncated = true;
                break;
            };
            match read_name_at(msg, (hi << 8) | lo as usize) {
                Some(resolved) => labels.extend(resolved),
                None => unresolved = true,
            }
            pos += 2;
            break;
        }
        if len & 0xC0 != 0 {
            // Extended label type, not a compression pointer: give up on
            // the name but still try the type bitmaps below.
            truncated = true;
            break;
        }
        let len = len as usize;
        pos += 1;
        match rdata.get(pos..pos + len) {
            Some(label) => labels.push(String::from_utf8_lossy(label).into_owned()),
            None => {
                truncated = true;
                break;
            }
        }
        pos += len;
    }
    let mut name = labels.join(".");
    if !name.is_empty() {
        name.push('.');
    }
    if unresolved || name.is_empty() {
        name.push('…');
    }
    if truncated {
        return name;
    }

    // Type bit maps: (window, bitmap-len, bitmap...).
    let mut types = Vec::new();
    while pos + 2 <= rdata.len() {
        let window = rdata[pos] as u16;
        let blen = rdata[pos + 1] as usize;
        pos += 2;
        if blen == 0 || pos + blen > rdata.len() {
            break;
        }
        for (i, &byte) in rdata[pos..pos + blen].iter().enumerate() {
            for bit in 0..8u16 {
                if byte & (0x80 >> bit) != 0 {
                    let rrtype = RecordType::from(window * 256 + i as u16 * 8 + bit);
                    types.push(rtype_label(rrtype));
                }
            }
        }
        pos += blen;
    }

    if types.is_empty() {
        name
    } else {
        format!("{name} {}", types.join(" "))
    }
}

/// Read a (possibly compressed) domain name starting at absolute `offset`
/// in `msg`, returning its labels. Pointer loops, excessive depth, and
/// overruns all yield None instead of hanging or panicking, so a corrupt
/// name only affects its own display string.
fn read_name_at(msg: &[u8], offset: usize) -> Option<Vec<String>> {
    let mut labels = Vec::new();
    let mut pos = offset;
    let mut visited: Vec<usize> = Vec::new();
    loop {
        let len = *msg.get(pos)?;
        if len == 0 {
            break;
        }
        if len & 0xC0 == 0xC0 {
            // Compression pointer: 14-bit absolute offset into the message.
            let target = (((len & 0x3F) as usize) << 8) | (*msg.get(pos + 1)? as usize);
            if visited.contains(&target) || visited.len() >= 32 {
                return None;
            }
            visited.push(target);
            pos = target;
            continue;
        }
        if len & 0xC0 != 0 {
            // Extended label type: not a plain name label.
            return None;
        }
        let len = len as usize;
        pos += 1;
        let label = msg.get(pos..pos + len)?;
        labels.push(String::from_utf8_lossy(label).into_owned());
        if labels.len() > 127 {
            return None;
        }
        pos += len;
    }
    Some(labels)
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

    fn known_answer(owner: &str, target: &str, ttl: u32) -> Record {
        let target = Name::from_ascii(target).unwrap();
        Record::from_rdata(
            Name::from_ascii(owner).unwrap(),
            ttl,
            RData::PTR(hickory_proto::rr::rdata::PTR(target)),
        )
    }

    fn test_source() -> std::net::SocketAddr {
        "192.168.178.60:5353".parse().unwrap()
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
        let mut q = Message::new(0, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("svc._http._tcp.local.").unwrap(),
            RecordType::PTR,
        ));
        q.add_answer(known_answer(
            "svc._http._tcp.local.",
            "Inst.svc._http._tcp.local.",
            120,
        ));
        let ev = parse_packet(&q.to_vec().unwrap(), test_source(), "enx", 2).unwrap();
        // The known answer must not become a sighting; the question stays.
        assert!(ev.records.is_empty());
        assert_eq!(ev.questions.len(), 1);
        assert_eq!(ev.questions[0].name, "svc._http._tcp.local.");
        assert!(!ev.questions[0].qu);
        // ... but the KA is retained for §7.3 duplicate suppression.
        assert_eq!(ev.query_kas.len(), 1);
        assert_eq!(ev.query_kas[0].rdata, "Inst.svc._http._tcp.local.");
        assert_eq!(ev.query_kas[0].iface, "enx");

        let mut r = Message::new(0, MessageType::Response, OpCode::Query);
        r.add_answer(known_answer(
            "svc._http._tcp.local.",
            "Inst.svc._http._tcp.local.",
            120,
        ));
        let ev = parse_packet(&r.to_vec().unwrap(), test_source(), "enx", 2).unwrap();
        assert_eq!(ev.records.len(), 1);
        assert_eq!(ev.records[0].rdata, "Inst.svc._http._tcp.local.");
        assert_eq!(ev.records[0].iface, "enx");
        assert!(ev.questions.is_empty());
        assert!(ev.query_kas.is_empty());
    }

    #[test]
    fn query_qu_bit_is_parsed() {
        let mut q = Message::new(0, MessageType::Query, OpCode::Query);
        let mut query = Query::query(
            Name::from_ascii("svc._http._tcp.local.").unwrap(),
            RecordType::PTR,
        );
        query.set_mdns_unicast_response(true);
        q.add_query(query);
        let ev = parse_packet(&q.to_vec().unwrap(), test_source(), "enx", 2).unwrap();
        assert_eq!(ev.questions.len(), 1);
        assert!(ev.questions[0].qu);
    }

    fn flush_response(flush: bool) -> Event {
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        let mut rec = Record::from_rdata(
            Name::from_ascii("test.local.").unwrap(),
            120,
            RData::A(Ipv4Addr::new(192, 168, 1, 10).into()),
        );
        rec.mdns_cache_flush = flush;
        msg.add_answer(rec);
        parse_packet(&msg.to_vec().unwrap(), test_source(), "", 7).unwrap()
    }

    #[test]
    fn response_flush_bit_survives_parse() {
        // hickory-proto strips the top CLASS bit at decode into
        // the mdns_cache_flush field; reading dns_class directly always
        // yields a clear bit (RFC 6762 §10.2).
        assert!(flush_response(true).records[0].flush_bit);
        assert!(!flush_response(false).records[0].flush_bit);
    }

    #[test]
    fn packet_index_survives_parse_without_name() {
        // flush_response parses with ("", 7): no name, index kept.
        let ev = flush_response(false);
        assert_eq!(ev.records.len(), 1);
        assert!(ev.records[0].iface.is_empty());
        assert_eq!(ev.records[0].ifindex, 7);
    }

    #[test]
    fn query_ka_flush_bit_survives_parse() {
        let mut q = Message::new(0, MessageType::Query, OpCode::Query);
        q.add_query(Query::query(
            Name::from_ascii("test.local.").unwrap(),
            RecordType::A,
        ));
        let mut ka = Record::from_rdata(
            Name::from_ascii("test.local.").unwrap(),
            120,
            RData::A(Ipv4Addr::new(192, 168, 1, 10).into()),
        );
        ka.mdns_cache_flush = true;
        q.add_answer(ka);
        let ev = parse_packet(&q.to_vec().unwrap(), test_source(), "", 7).unwrap();
        assert!(ev.records.is_empty());
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

    /// Message bytes with "host.local." at offset 20 for pointer tests.
    fn msg_with_host_at_20() -> Vec<u8> {
        let mut msg = vec![0u8; 64];
        msg[20] = 4;
        msg[21..25].copy_from_slice(b"host");
        msg[25] = 5;
        msg[26..31].copy_from_slice(b"local");
        msg[31] = 0;
        msg
    }

    /// Bitmap covering only A (type 1): window 0, len 1, 0x40.
    fn a_bitmap() -> Vec<u8> {
        vec![0, 1, 0x40]
    }

    fn inline_host_rdata() -> Vec<u8> {
        let mut r = vec![4];
        r.extend_from_slice(b"host");
        r.push(5);
        r.extend_from_slice(b"local");
        r.push(0);
        r.extend(a_bitmap());
        r
    }

    #[test]
    fn nsec_inline_name_unchanged() {
        // Pre-existing rendering must not change: no pointers involved,
        // so the message context is never consulted.
        assert_eq!(decode_nsec(&inline_host_rdata(), &[]), "host.local. A");
    }

    #[test]
    fn nsec_pointer_resolves_against_message() {
        let msg = msg_with_host_at_20();
        let mut rdata = vec![0xC0, 20];
        rdata.extend(a_bitmap());
        assert_eq!(decode_nsec(&rdata, &msg), "host.local. A");
    }

    #[test]
    fn nsec_prefix_plus_pointer_suffix() {
        let msg = msg_with_host_at_20();
        let mut rdata = vec![3];
        rdata.extend_from_slice(b"sub");
        rdata.extend([0xC0, 20]);
        rdata.extend(a_bitmap());
        assert_eq!(decode_nsec(&rdata, &msg), "sub.host.local. A");
    }

    #[test]
    fn nsec_dangling_pointer_renders_ellipsis() {
        let msg = vec![0u8; 64];
        let mut rdata = vec![0xC0, 200];
        rdata.extend(a_bitmap());
        assert_eq!(decode_nsec(&rdata, &msg), "… A");
    }

    #[test]
    fn nsec_pointer_loop_terminates() {
        let mut msg = vec![0u8; 64];
        msg[10] = 0xC0;
        msg[11] = 10;
        let mut rdata = vec![0xC0, 10];
        rdata.extend(a_bitmap());
        assert_eq!(decode_nsec(&rdata, &msg), "… A");
    }

    #[test]
    fn nsec_truncated_rdata_renders_ellipsis() {
        assert_eq!(decode_nsec(&[4, b't'], &[]), "…");
    }

    #[test]
    fn response_nsec_shows_resolved_name_and_iface() {
        let owner = Name::from_ascii("host.local.").unwrap();
        let mut msg = Message::new(0, MessageType::Response, OpCode::Query);
        let nsec = Record::from_rdata(
            owner,
            120,
            RData::Unknown {
                code: RecordType::NSEC,
                rdata: hickory_proto::rr::rdata::NULL::with(inline_host_rdata()),
            },
        );
        msg.add_answer(nsec);
        let raw = msg.to_vec().unwrap();
        let addr: SocketAddr = "192.168.178.5:5353".parse().unwrap();
        let ev = parse_packet(&raw, addr, "br0", 3).unwrap();
        assert_eq!(ev.records.len(), 1);
        assert_eq!(ev.records[0].rdata, "host.local. A");
        assert_eq!(ev.records[0].iface, "br0");
        assert!(ev.questions.is_empty());
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
    fn link_stats_lists_are_sorted_and_disjoint() {
        let stats = link_stats();
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
}
