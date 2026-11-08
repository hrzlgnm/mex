use std::collections::HashSet;
use std::mem::MaybeUninit;
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
use socket2::{Domain, Protocol, SockAddr, Socket, Type};

const MDNS_V4: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_V6: Ipv6Addr = Ipv6Addr::new(0xff02, 0, 0, 0, 0, 0, 0, 0xfb);
const MDNS_PORT: u16 = 5353;

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
pub struct QueryRequest {
    pub name: String,
    pub record_type: RecordType,
    /// PTR target names to include as known-answer records (owner name = self.name)
    pub known_answers: Vec<(String, u32)>,
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

    let v4_interfaces = v4_interfaces();
    let tx4 = tx.clone();
    let dest_v4 = SocketAddr::from(SocketAddrV4::new(MDNS_V4, MDNS_PORT));
    thread::spawn(move || {
        let socket = match create_v4_socket() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mex: v4 socket: {e}");
                return;
            }
        };
        for (name, ip) in &v4_interfaces {
            if let Err(e) = socket.join_multicast_v4(&MDNS_V4, ip) {
                eprintln!("mex: v4 mcast {name}: {e}");
            }
        }
        listen(&socket, tx4, rx_v4, dest_v4);
    });

    let v6_interfaces = v6_interfaces();
    let dest_v6 = SocketAddr::from(SocketAddrV6::new(MDNS_V6, MDNS_PORT, 0, 0));
    thread::spawn(move || {
        let socket = match create_v6_socket() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("mex: v6 socket: {e}");
                return;
            }
        };
        for (name, idx) in &v6_interfaces {
            if let Err(e) = socket.join_multicast_v6(&MDNS_V6, *idx) {
                eprintln!("mex: v6 mcast {name}: {e}");
            }
        }
        listen(&socket, tx, rx_v6, dest_v6);
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

fn skipped_interface(name: &str) -> bool {
    name == "lo" || name.starts_with("docker") || name.starts_with("veth")
}

fn v4_interfaces() -> Vec<(String, Ipv4Addr)> {
    let mut out = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if skipped_interface(&iface.name) {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = iface.addr {
            out.push((iface.name, v4.ip));
        }
    }
    out
}

fn v6_interfaces() -> Vec<(String, u32)> {
    let mut out = Vec::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        if skipped_interface(&iface.name) {
            continue;
        }
        if let if_addrs::IfAddr::V6(v6) = iface.addr {
            if v6.ip.to_string().starts_with('f') {
                out.push((iface.name, iface.index.unwrap_or(0)));
            }
        }
    }
    out
}

fn create_v4_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    let addr = SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, MDNS_PORT);
    socket.bind(&addr.into())?;
    Ok(socket)
}

fn create_v6_socket() -> Result<Socket> {
    let socket = Socket::new(Domain::IPV6, Type::DGRAM, Some(Protocol::UDP))?;
    socket.set_reuse_address(true)?;
    let _ = socket.set_only_v6(true);
    socket.set_read_timeout(Some(Duration::from_millis(500)))?;
    let addr = SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, MDNS_PORT, 0, 0);
    socket.bind(&addr.into())?;
    Ok(socket)
}

fn listen(
    socket: &Socket,
    tx: mpsc::Sender<Event>,
    query_rx: mpsc::Receiver<QueryRequest>,
    dest: SocketAddr,
) {
    let mut buf = vec![MaybeUninit::uninit(); 65535];

    loop {
        // drain any pending outgoing queries
        while let Ok(req) = query_rx.try_recv() {
            send_query(socket, &req, dest);
        }

        match socket.recv_from(&mut buf) {
            Ok((len, sockaddr)) => {
                let addr = match sockaddr.as_socket() {
                    Some(a) => a,
                    None => continue,
                };
                let raw: Vec<u8> = buf[..len]
                    .iter()
                    .map(|x| unsafe { x.assume_init() })
                    .collect();

                if let Some(ev) = parse_packet(&raw, addr) {
                    if tx.send(ev).is_err() {
                        break;
                    }
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock
                || e.kind() == std::io::ErrorKind::TimedOut =>
            {
                continue;
            }
            Err(e) => {
                eprintln!("mex: recv error: {e}");
                thread::sleep(Duration::from_secs(1));
            }
        }
    }
}

fn send_query(socket: &Socket, req: &QueryRequest, dest: SocketAddr) {
    let qname = match Name::from_ascii(format!("{}.", req.name)) {
        Ok(n) => n,
        Err(_) => return,
    };
    let mut msg = Message::new();
    msg.add_query(Query::query(qname.clone(), req.record_type));
    msg.set_message_type(MessageType::Query);
    msg.set_recursion_desired(false);
    msg.set_id(0);

    for (ka_rdata, ka_ttl) in &req.known_answers {
        if let Ok(rdata) = Name::from_ascii(format!("{ka_rdata}.")) {
            let mut rec = Record::with(qname.clone(), req.record_type, *ka_ttl);
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

fn parse_packet(raw: &[u8], source: SocketAddr) -> Option<Event> {
    let msg = Message::from_bytes(raw).ok()?;

    let mut records = Vec::new();

    for rec in msg.answers().iter().chain(msg.name_servers()).chain(msg.additionals()) {
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
            received_at: Instant::now(),
        });
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
            format!("{} {} {} {}", srv.priority(), srv.weight(), srv.port(), unescape(&srv.target().to_string()))
        }
        Some(RData::TXT(txt)) => txt
            .iter()
            .map(|b| String::from_utf8_lossy(b).to_string())
            .collect::<Vec<_>>()
            .join("; "),
        Some(RData::PTR(n)) => unescape(&n.to_string()),
        Some(RData::CNAME(n)) => unescape(&n.to_string()),
        Some(RData::NS(n)) => unescape(&n.to_string()),
        Some(RData::MX(mx)) => format!("{} {}", mx.preference(), unescape(&mx.exchange().to_string())),
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


