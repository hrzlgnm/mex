use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV4, SocketAddrV6};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use anyhow::Result;
use hickory_proto::op::{Message, MessageType, Query};
use hickory_proto::rr::{DNSClass, Name, RData, Record, RecordType};

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
    pub ttl: u32,
    pub rdata: String,
    /// Standalone wire encoding of this record, captured at parse time so
    /// the hex view doesn't depend on the shared packet buffer.
    pub wire: Vec<u8>,
    pub source: SocketAddr,
    /// Name of the interface the packet arrived on (e.g. `"br0"`), from
    /// IP_PKTINFO. Empty when unknown; used only for display/diagnosis.
    pub iface: String,
    pub received_at: Instant,
}

#[derive(Debug, Clone)]
pub struct Event {
    pub records: Vec<RawRecord>,
    pub questions: Vec<RawRecord>,
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

pub fn spawn() -> Result<(QueryTx, mpsc::Receiver<Event>)> {
    let (tx, rx) = mpsc::channel();
    let (tx_v4, rx_v4) = mpsc::channel();
    let (tx_v6, rx_v6) = mpsc::channel();

    let tx4 = tx.clone();
    thread::spawn(move || {
        let socket = match create_v4_socket() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mex: v4 socket: {e}");
                return;
            }
        };
        listen(&socket, tx4, rx_v4, Family::V4);
    });

    thread::spawn(move || {
        let socket = match create_v6_socket() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mex: v6 socket: {e}");
                return;
            }
        };
        listen(&socket, tx, rx_v6, Family::V6);
    });

    Ok((
        QueryTx {
            v4: tx_v4,
            v6: tx_v6,
        },
        rx,
    ))
}

pub fn local_ips() -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        out.insert(iface.addr.ip());
    }
    out
}

fn iface_names() -> HashMap<u32, String> {
    // Unfiltered on purpose: this only labels observed packets for
    // display (including looped-back ones), it does not select links.
    let mut out = HashMap::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if let Some(idx) = iface.index {
            out.entry(idx).or_insert(iface.name);
        }
    }
    out
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
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    socket.bind(&addr.into())?;
    Ok(socket)
}

fn create_v6_socket() -> Result<PktInfoUdpSocket> {
    let socket = PktInfoUdpSocket::new(Domain::IPV6)?;
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
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
    family: Family,
) {
    let mut buf = vec![0u8; 65535];
    let mut ifaces_v4: Vec<(String, Ipv4Addr)> = Vec::new();
    let mut ifaces_v6: Vec<(String, u32)> = Vec::new();
    let mut ifnames: HashMap<u32, String> = HashMap::new();
    let mut last_refresh: Option<Instant> = None;

    loop {
        if last_refresh
            .map(|t| t.elapsed() >= IFACE_REFRESH)
            .unwrap_or(true)
        {
            last_refresh = Some(Instant::now());
            ifnames = iface_names();
            match family {
                Family::V4 => {
                    ifaces_v4 = v4_interfaces();
                    // Join unconditionally: joins are idempotent, and a
                    // rejoin is required after the interface went away
                    // and came back (same name, new incarnation).
                    for (name, ip) in &ifaces_v4 {
                        if let Err(e) = socket.join_multicast_v4(&MDNS_V4, ip) {
                            eprintln!("mex: v4 mcast {name}: {e}");
                        }
                    }
                }
                Family::V6 => {
                    ifaces_v6 = v6_interfaces();
                    for (name, idx) in &ifaces_v6 {
                        if let Err(e) = socket.join_multicast_v6(&MDNS_V6, *idx) {
                            eprintln!("mex: v6 mcast {name}: {e}");
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
                let iface = ifnames
                    .get(&(info.if_index as u32))
                    .map(String::as_str)
                    .unwrap_or("");
                if let Some(ev) = parse_packet(&raw, info.addr_src, iface) {
                    if tx.send(ev).is_err() {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(50));
            }
            Err(e) => {
                eprintln!("mex: recv error: {e}");
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
    let mut msg = Message::new();
    let mut query = Query::query(qname.clone(), req.record_type);
    query.set_mdns_unicast_response(req.qu);
    msg.add_query(query);
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(false);
    msg.set_id(0);

    for (ka_target, ka_ttl) in known_answers_for_iface(&req.known_answers, egress_iface) {
        let target = ka_target.trim_end_matches('.');
        if let Ok(rdata) = Name::from_ascii(format!("{target}.")) {
            let mut rec = Record::with(qname.clone(), req.record_type, ka_ttl);
            rec.set_data(Some(RData::PTR(hickory_proto::rr::rdata::PTR(rdata))));
            rec.set_dns_class(DNSClass::IN);
            msg.add_answer(rec);
        }
    }

    let bytes = match msg.to_vec() {
        Ok(b) => b,
        Err(_) => return,
    };
    let _ = socket.send_to(&bytes, &SockAddr::from(dest));
}

fn parse_packet(raw: &[u8], source: SocketAddr, iface: &str) -> Option<Event> {
    let msg = Message::from_bytes(raw).ok()?;

    let mut records = Vec::new();

    // Only responses carry authoritative records. Queries may carry the
    // same records as known answers (RFC 6762 §7.1 suppression), which
    // are beliefs, not facts: the querier (often ourselves, via
    // multicast loopback) is not their source. Filing them would conjure
    // phantom sightings on links the device never touched.
    if msg.message_type() == MessageType::Response {
        for rec in msg
            .answers()
            .iter()
            .chain(msg.name_servers())
            .chain(msg.additionals())
        {
            let class: u16 = rec.dns_class().into();
            records.push(RawRecord {
                name: unescape(&rec.name().to_string()),
                rtype: u16::from(rec.record_type()),
                rtype_str: rtype_label(rec.record_type()),
                flush_bit: class & 0x8000 != 0,
                ttl: rec.ttl(),
                rdata: rdata_label(rec.data()),
                wire: rec.to_bytes().unwrap_or_default(),
                source,
                iface: iface.to_string(),
                received_at: Instant::now(),
            });
        }
    }

    let mut questions = Vec::new();
    for q in msg.queries() {
        questions.push(RawRecord {
            name: unescape(&q.name().to_string()),
            rtype: u16::from(q.query_type()),
            rtype_str: rtype_label(q.query_type()),
            flush_bit: false,
            ttl: 0,
            rdata: String::new(),
            wire: Vec::new(),
            source,
            iface: iface.to_string(),
            received_at: Instant::now(),
        });
    }

    Some(Event {
        records,
        questions,
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

fn rdata_label(data: Option<&RData>) -> String {
    match data {
        Some(RData::A(ip)) => ip.to_string(),
        Some(RData::AAAA(ip)) => ip.to_string(),
        Some(RData::SRV(srv)) => {
            format!(
                "{} {} {} {}",
                srv.priority(),
                srv.weight(),
                srv.port(),
                unescape(&srv.target().to_string())
            )
        }
        Some(RData::TXT(txt)) => txt
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<Vec<_>>()
            .join("; "),
        Some(RData::PTR(n)) => unescape(&n.to_string()),
        Some(RData::CNAME(n)) => unescape(&n.to_string()),
        Some(RData::NS(n)) => unescape(&n.to_string()),
        Some(RData::MX(mx)) => format!(
            "{} {}",
            mx.preference(),
            unescape(&mx.exchange().to_string())
        ),
        Some(RData::SOA(soa)) => format!(
            "{} {} {} {} {} {} {}",
            unescape(&soa.mname().to_string()),
            unescape(&soa.rname().to_string()),
            soa.serial(),
            soa.refresh(),
            soa.retry(),
            soa.expire(),
            soa.minimum()
        ),
        Some(RData::HINFO(h)) => {
            let cpu = String::from_utf8_lossy(h.cpu());
            let os = String::from_utf8_lossy(h.os());
            format!("{cpu} {os}")
        }
        Some(RData::SVCB(svcb)) => unescape(&svcb.target_name().to_string()),
        Some(RData::Unknown { code, rdata }) if *code == RecordType::NSEC => {
            decode_nsec(rdata.anything())
        }
        _ => String::new(),
    }
}

/// Decode NSEC rdata (next name + type bit maps, RFC 4034 §4.1) for display:
/// "<next-name> <TYPE>...". Compression pointers in the next name can't be
/// resolved from rdata alone, so those render as "…".
fn decode_nsec(rdata: &[u8]) -> String {
    let mut pos = 0;
    let mut labels = Vec::new();
    let mut compressed = false;
    // Next domain name in wire format.
    let mut truncated = false;
    while let Some(&len) = rdata.get(pos) {
        if len == 0 {
            pos += 1;
            break;
        }
        if len & 0xC0 != 0 {
            // Compression pointer (or extended label type): target lives
            // outside rdata, so the name can't be resolved here.
            compressed = true;
            if len & 0xC0 == 0xC0 {
                pos += 2;
            } else {
                truncated = true;
            }
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
    if compressed || name.is_empty() {
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
        let mut rec = Record::with(Name::from_ascii(owner).unwrap(), RecordType::PTR, ttl);
        let target = Name::from_ascii(target).unwrap();
        rec.set_data(Some(RData::PTR(hickory_proto::rr::rdata::PTR(target))));
        rec.set_dns_class(DNSClass::IN);
        rec
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
        let mut q = Message::new();
        q.add_query(Query::query(
            Name::from_ascii("svc._http._tcp.local.").unwrap(),
            RecordType::PTR,
        ));
        q.set_message_type(MessageType::Query);
        q.add_answer(known_answer(
            "svc._http._tcp.local.",
            "Inst.svc._http._tcp.local.",
            120,
        ));
        let ev = parse_packet(&q.to_vec().unwrap(), test_source(), "enx").unwrap();
        // The known answer must not become a sighting; the question stays.
        assert!(ev.records.is_empty());
        assert_eq!(ev.questions.len(), 1);
        assert_eq!(ev.questions[0].name, "svc._http._tcp.local.");

        let mut r = Message::new();
        r.set_message_type(MessageType::Response);
        r.add_answer(known_answer(
            "svc._http._tcp.local.",
            "Inst.svc._http._tcp.local.",
            120,
        ));
        let ev = parse_packet(&r.to_vec().unwrap(), test_source(), "enx").unwrap();
        assert_eq!(ev.records.len(), 1);
        assert_eq!(ev.records[0].rdata, "Inst.svc._http._tcp.local.");
        assert_eq!(ev.records[0].iface, "enx");
        assert!(ev.questions.is_empty());
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
}
