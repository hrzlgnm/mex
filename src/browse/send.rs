// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// What a send outcome means for the log, after dedup.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum SendLog {
    /// First failure of this kind on this link: log it at error.
    Failed,
    /// The link sent successfully after failing: log one recovery line.
    Recovered,
}

/// The socket call a send-path failure came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(super) enum SendOp {
    /// Pinning the multicast egress interface.
    Pin,
    /// Sending the query copy.
    Send,
}

/// How long a sent query copy can take to loop back to us.
pub(super) const OWN_COPY_WINDOW: Duration = Duration::from_secs(2);

/// Bound on remembered sent copies (one per link per query).
pub(super) const OWN_COPY_CAP: usize = 512;

/// Recently sent query copies, by exact bytes. With multicast loop on,
/// every copy we send comes back from a local address; address alone
/// can't tell it from a local responder's own query (avahi asks from the
/// same `ip:5353`), so our copies are matched by content. Each sent copy
/// drops exactly one received copy, so an identical query from another
/// local querier is still seen.
#[derive(Debug, Default)]
pub(super) struct SentCopies {
    pub(super) recent: VecDeque<(u64, Instant)>,
}

pub(super) fn copy_digest(bytes: &[u8]) -> u64 {
    use std::hash::{Hash, Hasher};
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    bytes.hash(&mut hasher);
    hasher.finish()
}

impl SentCopies {
    /// Remember one copy that was actually sent.
    pub(super) fn record(&mut self, bytes: &[u8], now: Instant) {
        self.prune(now);
        if self.recent.len() >= OWN_COPY_CAP {
            self.recent.pop_front();
        }
        self.recent.push_back((copy_digest(bytes), now));
    }

    /// Whether `bytes` is one of our own copies looping back; consumes
    /// the match so it can only drop one received packet.
    pub(super) fn take(&mut self, bytes: &[u8], now: Instant) -> bool {
        self.prune(now);
        let digest = copy_digest(bytes);
        match self.recent.iter().position(|(d, _)| *d == digest) {
            Some(i) => {
                self.recent.remove(i);
                true
            }
            None => false,
        }
    }

    pub(super) fn prune(&mut self, now: Instant) {
        while self
            .recent
            .front()
            .is_some_and(|(_, at)| now.saturating_duration_since(*at) > OWN_COPY_WINDOW)
        {
            self.recent.pop_front();
        }
    }
}

/// Send-failure dedup per (family, link): a broken link logs each
/// (operation, error kind) once until it sends successfully again, then
/// logs one recovery line, instead of once per query. Links that leave
/// the interface list forget their state.
#[derive(Debug, Default)]
pub(super) struct SendFailures {
    pub(super) failing: HashMap<(Family, String), HashSet<(SendOp, std::io::ErrorKind)>>,
}

impl SendFailures {
    /// Record a failed pin or send on `iface`, returning `Failed` the
    /// first time this (operation, kind) fails since the link last sent.
    pub(super) fn record_failure(
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
    pub(super) fn record_success(&mut self, family: Family, iface: &str) -> Option<SendLog> {
        self.failing
            .remove(&(family, iface.to_string()))
            .map(|_| SendLog::Recovered)
    }

    /// Forget links of `family` no longer in `links`.
    pub(super) fn retain_links<'a>(
        &mut self,
        family: Family,
        links: impl IntoIterator<Item = &'a str>,
    ) {
        let keep: HashSet<&str> = links.into_iter().collect();
        self.failing
            .retain(|(f, name), _| *f != family || keep.contains(name.as_str()));
    }
}

/// The interface a query copy is pinned to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Egress {
    V4(Ipv4Addr),
    V6(u32),
}

/// The two socket calls the send path makes, so the per-link pin/send
/// sequence can be checked without a network.
pub(super) trait QuerySocket {
    /// Pin the multicast egress interface (socket-wide).
    fn pin(&self, egress: Egress) -> std::io::Result<()>;
    fn send_to(&self, bytes: &[u8], dest: SocketAddr) -> std::io::Result<()>;
}

/// One query copy: the link it leaves on, its destination, and the
/// egress interface pinned for it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct SendTarget<'a> {
    pub(super) link: &'a str,
    pub(super) dest: SocketAddr,
    pub(super) egress: Egress,
}

/// One target per usable link of `family`. An empty list means no
/// target at all: no copy is sent unpinned (it would leave by the
/// kernel's default multicast interface, possibly one the user did not
/// select). The interface refresh picks links up again once they gain
/// an address or come up.
pub(super) fn send_targets<'a>(
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

/// One copy of each packet of the batch per usable link, each forced out
/// its own link: without the per-packet interface the kernel sends
/// everything via the default multicast interface and other links (e.g.
/// a bridge) never see our queries. The batch is encoded per link, since
/// known answers are scoped to it (`encode_batch`). No usable link means
/// no copy (`send_targets`). Returns one `OwnSend` per copy that left
/// without error (#431), with every question it asked: a failed pin or
/// send, or a question that can't be encoded, reports nothing. An IPv4
/// copy's link index is left 0 for the caller, which knows the names.
pub(super) fn send_on_all_interfaces(
    socket: &impl QuerySocket,
    batch: &[QueryRequest],
    family: Family,
    ifaces_v4: &[(String, Ipv4Addr)],
    ifaces_v6: &[(String, u32)],
    failures: &mut SendFailures,
    sent_copies: &mut SentCopies,
) -> Vec<OwnSend> {
    let family_label = family.label();
    let mut sent_ok = Vec::new();
    for target in send_targets(family, ifaces_v4, ifaces_v6) {
        let SendTarget { link, dest, egress } = target;
        // Only the questions still asked on this link (#441); none, and
        // the link gets no copy at all.
        let on_link: std::borrow::Cow<'_, [QueryRequest]> =
            if batch.iter().all(|q| q.links.is_empty()) {
                std::borrow::Cow::Borrowed(batch)
            } else {
                std::borrow::Cow::Owned(
                    batch
                        .iter()
                        .filter(|q| q.links.is_empty() || q.links.iter().any(|l| l == link))
                        .cloned()
                        .collect(),
                )
            };
        if on_link.is_empty() {
            continue;
        }
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
        for (bytes, asked) in encode_batch(&on_link, link) {
            match socket.send_to(&bytes, dest) {
                Ok(()) => {
                    let now = Instant::now();
                    sent_copies.record(&bytes, now);
                    sent_ok.push(OwnSend {
                        questions: asked
                            .iter()
                            .map(|&i| (on_link[i].name.clone(), u16::from(on_link[i].record_type)))
                            .collect(),
                        iface: link.to_string(),
                        // An IPv6 copy is pinned by index; an IPv4 one by
                        // address, so the listener fills its index in.
                        ifindex: match egress {
                            Egress::V6(idx) => idx,
                            Egress::V4(_) => 0,
                        },
                        v6: family == Family::V6,
                        sent_at: now,
                    });
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
    sent_ok
}

/// Known answers relevant to one egress interface: suppression only
/// helps if a responder on *that* link holds the record, so answers
/// learned elsewhere are left out (empty origin means unknown, sent
/// everywhere; an empty egress means an unknown link, keep everything).
pub(super) fn known_answers_for_iface<'a>(
    kas: &'a [KnownAnswer],
    iface: &str,
) -> Vec<(&'a str, u32)> {
    kas.iter()
        .filter(|ka| ka.iface.is_empty() || iface.is_empty() || ka.iface == iface)
        .map(|ka| (ka.target.as_str(), ka.ttl))
        .collect()
}

/// Wire name for a name as mex keys it: presentation form
/// (`display_name`, `instance_name`), split on unescaped dots with each
/// escape dropped, so `\.` stays inside its label (#386). Every owner
/// mex queries for comes from a parsed name or an `instance_name`, so
/// the split is exact: `a\.b._x._tcp.local` and `a.b._x._tcp.local`
/// are two names. Labels go in as raw bytes, so instance names with
/// spaces and punctuation encode fine. `None` means the name cannot go
/// on the wire: an empty or over-long label, or a name longer than
/// `MAX_NAME_OCTETS` (labels are built unchecked, so simple-dns would
/// write it out anyway, as a malformed packet).
pub(super) fn wire_name(name: &str) -> Option<simple_dns::Name<'static>> {
    let parts = presentation_labels(name);
    let mut labels = Vec::with_capacity(parts.len());
    // The root label's zero octet.
    let mut octets = 1;
    for part in &parts {
        let bytes = part.as_bytes();
        if bytes.is_empty() || bytes.len() > 63 {
            return None;
        }
        // Length octet plus the label itself.
        octets += 1 + bytes.len();
        labels.push(simple_dns::Label::new_unchecked(bytes));
    }
    if octets > MAX_NAME_OCTETS {
        return None;
    }
    Some(simple_dns::Name::new_with_labels(&labels).into_owned())
}

/// Longest name on the wire, counting each label's length octet and the
/// root's zero octet (RFC 1035 §3.1).
pub(super) const MAX_NAME_OCTETS: usize = 255;

/// Largest UDP payload we will emit (RFC 6762 §17: packets MUST NOT
/// exceed 9000 bytes including IP+UDP headers; the 40-byte IPv6 header
/// is the roomier deduction).
pub(super) const MAX_QUERY_BYTES: usize = 9000 - 40 - 8;

/// One question ready for the wire on one egress interface: its owner
/// name, type, QU bit and its known answers scoped to that interface.
pub(super) struct WireQuestion {
    qname: simple_dns::Name<'static>,
    record_type: TYPE,
    qu: bool,
    kas: Vec<(simple_dns::Name<'static>, u32)>,
}

impl WireQuestion {
    /// `req` as it goes out on `egress_iface`. `None` means the owner
    /// name cannot go on the wire (see `wire_name`), which is logged
    /// because the scheduler has already counted the query as sent; an
    /// unencodable known answer is skipped, the rest kept.
    pub(super) fn new(req: &QueryRequest, egress_iface: &str) -> Option<Self> {
        let Some(qname) = wire_name(&req.name) else {
            log::warn!(
                "mex: cannot encode {:?} query name {:?}",
                u16::from(req.record_type),
                req.name
            );
            return None;
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
        Some(Self {
            qname,
            record_type: req.record_type,
            qu: req.qu,
            kas,
        })
    }
}

/// Encode one query for an egress interface. `None` means the owner name
/// cannot go on the wire (see `wire_name`) or the codec failed; that is
/// logged because the scheduler has already counted the query as sent.
///
/// Names compress against byte-identical repeats (differing-case names
/// are written in full, so wire case is preserved), which keeps dense
/// known-answer lists small. If the packet still exceeds
/// `MAX_QUERY_BYTES`, known answers are shed — never the question — and
/// the cut is logged: a short refresh still elicits answers, while a
/// dropped one would lose the refresh silently (EMSGSIZE on send, past
/// the 65507-byte kernel limit). Full multipacket known-answer
/// suppression (RFC 6762 §7.2, TC-bit follow-ups) is future work.
///
/// The send path packs batches (`encode_batch`); this one-question form
/// is the tests' view of a single question on the wire.
#[cfg(test)]
pub(super) fn encode_query(req: &QueryRequest, egress_iface: &str) -> Option<Vec<u8>> {
    encode_query_into(&mut std::io::Cursor::new(Vec::new()), req, egress_iface)
}

/// `encode_query` through `sink`, which every build (including the
/// known-answer truncation retries) writes to.
#[cfg(test)]
pub(super) fn encode_query_into(
    sink: &mut dyn WireSink,
    req: &QueryRequest,
    egress_iface: &str,
) -> Option<Vec<u8>> {
    let question = WireQuestion::new(req, egress_iface)?;
    encode_alone(sink, question, &req.name)
}

/// One question in a packet of its own, shedding known answers (halving,
/// logged) while it is over `MAX_QUERY_BYTES`, never the question.
fn encode_alone(sink: &mut dyn WireSink, mut q: WireQuestion, name: &str) -> Option<Vec<u8>> {
    let mut bytes = build_packet_into(sink, &[&q])?;
    if bytes.len() > MAX_QUERY_BYTES {
        let total = q.kas.len();
        let mut n = total;
        while n > 0 {
            n /= 2;
            q.kas.truncate(n);
            bytes = build_packet_into(sink, &[&q])?;
            if bytes.len() <= MAX_QUERY_BYTES {
                break;
            }
        }
        log::warn!(
            "mex: truncated known answers for {name} to {} of {total} ({} bytes)",
            q.kas.len(),
            bytes.len()
        );
    }
    Some(bytes)
}

/// One encoded packet of a batch, with the indexes (into the batch) of
/// the questions it asks.
pub(super) type BatchPacket = (Vec<u8>, Vec<usize>);

/// Encode the questions due together (#430) for one egress interface:
/// as few packets as fit, all questions in the Question section and each
/// one's interface-scoped known answers in the Answer section, names
/// compressed across the packet. A packet that would exceed
/// `MAX_QUERY_BYTES` is closed and the question moves on to the next one,
/// whole with its known answers; only a question too large on its own
/// sheds known answers. An unencodable question is skipped (logged), the
/// rest still sent. A codec failure ends the batch: what was encoded
/// before it is kept.
pub(super) fn encode_batch(batch: &[QueryRequest], egress_iface: &str) -> Vec<BatchPacket> {
    encode_batch_into(&mut std::io::Cursor::new(Vec::new()), batch, egress_iface)
}

/// `encode_batch` through `sink`, which every build writes to.
pub(super) fn encode_batch_into(
    sink: &mut dyn WireSink,
    batch: &[QueryRequest],
    egress_iface: &str,
) -> Vec<BatchPacket> {
    let mut packets = Vec::new();
    // The packet being filled: its questions, their batch indexes, and
    // its bytes so far.
    let mut open: Vec<WireQuestion> = Vec::new();
    let mut open_idx: Vec<usize> = Vec::new();
    let mut open_bytes: Vec<u8> = Vec::new();
    for (i, req) in batch.iter().enumerate() {
        let Some(question) = WireQuestion::new(req, egress_iface) else {
            continue;
        };
        if !open.is_empty() {
            let with: Vec<&WireQuestion> = open.iter().chain([&question]).collect();
            let Some(bytes) = build_packet_into(sink, &with) else {
                break;
            };
            if bytes.len() <= MAX_QUERY_BYTES {
                open.push(question);
                open_idx.push(i);
                open_bytes = bytes;
                continue;
            }
            // Full: close it, the question starts the next one.
            packets.push((
                std::mem::take(&mut open_bytes),
                std::mem::take(&mut open_idx),
            ));
            open.clear();
        }
        let Some(bytes) = build_packet_into(sink, &[&question]) else {
            break;
        };
        if bytes.len() <= MAX_QUERY_BYTES {
            open.push(question);
            open_idx.push(i);
            open_bytes = bytes;
        } else {
            // Too large even alone: its own packet, known answers shed.
            let Some(bytes) = encode_alone(sink, question, &req.name) else {
                break;
            };
            packets.push((bytes, vec![i]));
        }
    }
    if !open.is_empty() {
        packets.push((open_bytes, open_idx));
    }
    packets
}

/// One query packet: question plus the given known answers, names
/// compressed. `None` only on codec failure (logged).
pub(super) fn build_query(
    qname: &simple_dns::Name<'_>,
    record_type: TYPE,
    qu: bool,
    kas: &[(simple_dns::Name<'_>, u32)],
) -> Option<Vec<u8>> {
    build_query_into(
        &mut std::io::Cursor::new(Vec::new()),
        qname,
        record_type,
        qu,
        kas,
    )
}

/// `build_query` through `sink`; the codec only fails when the sink
/// does.
pub(super) fn build_query_into(
    sink: &mut dyn WireSink,
    qname: &simple_dns::Name<'_>,
    record_type: TYPE,
    qu: bool,
    kas: &[(simple_dns::Name<'_>, u32)],
) -> Option<Vec<u8>> {
    let question = WireQuestion {
        qname: qname.clone().into_owned(),
        record_type,
        qu,
        kas: kas
            .iter()
            .map(|(rdata, ttl)| (rdata.clone().into_owned(), *ttl))
            .collect(),
    };
    build_packet_into(sink, &[&question])
}

/// One query packet asking `questions`, each one's known answers in the
/// Answer section, names compressed across the packet. `None` only on
/// codec failure (logged).
fn build_packet_into(mut sink: &mut dyn WireSink, questions: &[&WireQuestion]) -> Option<Vec<u8>> {
    let mut pkt = Packet::new_query(0);
    for q in questions {
        pkt.questions.push(simple_dns::Question::new(
            q.qname.clone(),
            QTYPE::TYPE(q.record_type),
            QCLASS::CLASS(CLASS::IN),
            q.qu,
        ));
    }
    for q in questions {
        for (rdata, ttl) in &q.kas {
            pkt.answers.push(ResourceRecord::new(
                q.qname.clone(),
                CLASS::IN,
                *ttl,
                RData::PTR(rdata.clone().into()),
            ));
        }
    }
    match pkt.write_compressed_to(&mut sink) {
        Ok(()) => Some(sink.take_bytes()),
        Err(e) => {
            let first = questions
                .first()
                .map(|q| q.qname.to_string())
                .unwrap_or_default();
            log::warn!("mex: cannot encode query for {first}: {e}");
            None
        }
    }
}

pub(crate) fn inferred_question_packet(name: &str, rtype: u16, qu: bool) -> Option<Vec<u8>> {
    let qname = wire_name(name)?;
    let record_type = record_type_from_u16(rtype)?;
    build_query(&qname, record_type, qu, &[])
}
