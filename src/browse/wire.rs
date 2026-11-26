// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// Whether a parsed DNS name holds bytes outside UTF-8. Must run on
/// raw label bytes at parse time: after lossy display a genuine U+FFFD
/// character and invalid bytes are indistinguishable.
pub(super) fn name_has_invalid_utf8(name: &simple_dns::Name<'_>) -> bool {
    name.get_labels()
        .iter()
        .any(|l| std::str::from_utf8(l.as_ref()).is_err())
}

/// Whether name-valued rdata holds non-UTF-8 bytes: the same set of
/// variants `rdata_label` renders as names. TXT values and HINFO strings
/// are excluded on purpose (opaque binary is legitimate there, and they
/// never become refresh query names). Only in-scope answer types are
/// decoded at all (`anomalies::is_mdns_answer_type`).
pub(super) fn rdata_has_invalid_utf8(rdata: &RData) -> bool {
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

/// Presentation form of a parsed DNS name (RFC 1035 §5.1): labels as
/// UTF-8 (lossy), each escaped by `escape_label`, joined by dots, with
/// a trailing dot. Non-UTF-8 bytes render as U+FFFD (RFC 6762 §16 names
/// are UTF-8). A dot inside a DNS-SD instance label (RFC 6763 §4.1.1)
/// stays `\.`, so the name keeps its label boundaries: it is the
/// identity every record, question and query owner is keyed by (#386).
/// Views show `unescape_name` of it; names without a dot or backslash
/// inside a label read the same either way.
pub(super) fn display_name(name: &simple_dns::Name<'_>) -> String {
    let mut out = String::new();
    for (i, label) in name.get_labels().iter().enumerate() {
        if i > 0 {
            out.push('.');
        }
        out.push_str(&escape_label(&String::from_utf8_lossy(label.as_ref())));
    }
    out.push('.');
    out
}

/// One label in presentation form (RFC 1035 §5.1, RFC 6763 §4.3): `\`
/// and `.` take a backslash, so a dot inside the label never reads as
/// a separator. Everything else stays as is (UTF-8 is not escaped).
pub(crate) fn escape_label(label: &str) -> String {
    let mut out = String::with_capacity(label.len());
    for c in label.chars() {
        if matches!(c, '.' | '\\') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// Labels of a presentation-form name: split on unescaped dots, each
/// escape dropped (`\X` is `X`). A trailing root dot adds no label.
pub(crate) fn presentation_labels(name: &str) -> Vec<String> {
    split_presentation(name).0
}

/// `presentation_labels` plus whether the name ends in the root (an
/// unescaped trailing dot).
fn split_presentation(name: &str) -> (Vec<String>, bool) {
    let mut labels = Vec::new();
    let mut label = String::new();
    let mut rooted = false;
    let mut chars = name.chars();
    while let Some(c) = chars.next() {
        rooted = c == '.';
        match c {
            '\\' => label.extend(chars.next()),
            '.' => labels.push(std::mem::take(&mut label)),
            _ => label.push(c),
        }
    }
    if !rooted {
        labels.push(label);
    }
    (labels, rooted)
}

/// Display form of a presentation-form name: escapes dropped, labels
/// joined by plain dots (the trailing root dot kept when present). For
/// views only: it is ambiguous where a label holds a dot.
pub(crate) fn unescape_name(name: &str) -> String {
    if !name.contains('\\') {
        return name.to_string();
    }
    let (labels, rooted) = split_presentation(name);
    let mut out = labels.join(".");
    if rooted {
        out.push('.');
    }
    out
}

/// View text of a record's rdata: the name it holds (PTR, CNAME and NS
/// targets, the SRV target, the NSEC next name) without escapes, like
/// `unescape_name`; any other rdata (TXT text) exactly as stored.
pub(crate) fn display_rdata(rtype: u16, rdata: &str) -> String {
    match rtype {
        2 | 5 | 12 | 33 | 47 => unescape_name(rdata),
        _ => rdata.to_string(),
    }
}

/// Whether `head`, the text of a presentation-form name before one of
/// its dots, ends in an unpaired backslash: then that dot is escaped
/// (inside a label), not a separator.
pub(crate) fn escapes_next(head: &str) -> bool {
    head.bytes().rev().take_while(|&b| b == b'\\').count() % 2 == 1
}

/// Presentation-form name of a service instance: its instance label
/// escaped (`escape_label`) and joined to its service type, which is
/// already in presentation form. Wire case; fold ASCII to compare. Two
/// instances share it only if they share both the instance label and
/// the type, so `a.b` of `_x._tcp.local` and `a` of `b._x._tcp.local`
/// stay apart (#386).
pub(crate) fn instance_name(instance: &str, service_type: &str) -> String {
    format!("{}.{service_type}", escape_label(instance))
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
    // link; our own looped-back copies are dropped on receive) is not their
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
pub(super) struct Ingress<'a> {
    pub(super) source: SocketAddr,
    pub(super) iface: &'a str,
    pub(super) ifindex: u32,
    pub(super) dst_is_multicast: bool,
}

/// One parsed resource record. Out-of-scope types
/// (`anomalies::is_mdns_answer_type` false) are never decoded: they keep
/// owner, type, class bits, TTL and their RDLENGTH (`rdlength=<n>`),
/// with no rdata bytes, so nothing downstream holds or interprets data
/// mex does not support.
pub(super) fn record_row(
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

pub(super) fn question_row(q: &Question<'_>, ing: Ingress<'_>) -> RawRecord {
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
pub(super) fn record_wire(rec: &ResourceRecord<'_>) -> Vec<u8> {
    record_wire_into(&mut std::io::Cursor::new(Vec::new()), rec)
}

/// `record_wire` through `sink`. Empty when the codec fails, which it
/// only does when the sink does: the hex pane then shows no bytes
/// instead of the app going down.
pub(super) fn record_wire_into(mut sink: &mut dyn WireSink, rec: &ResourceRecord<'_>) -> Vec<u8> {
    let mut pkt = Packet::new_reply(0);
    pkt.answers.push(rec.clone());
    match pkt.write_to(&mut sink) {
        Ok(()) => sink.take_bytes().get(12..).unwrap_or_default().to_vec(),
        Err(_) => Vec::new(),
    }
}

/// Where the encoders write: an in-memory buffer in the app, a failing
/// one in tests (the codec only fails on writer errors). Taken as a
/// trait object, so each encoder is compiled once and its success and
/// error arms count as one function's coverage.
pub(super) trait WireSink: std::io::Write + std::io::Seek {
    /// The bytes written so far, leaving the sink empty and ready for
    /// the next packet.
    fn take_bytes(&mut self) -> Vec<u8>;
}

impl WireSink for std::io::Cursor<Vec<u8>> {
    fn take_bytes(&mut self) -> Vec<u8> {
        // Rewind too: a write at the old position would pad with zeros.
        self.set_position(0);
        std::mem::take(self.get_mut())
    }
}

/// Type and RDLENGTH of one resource record, read from the packet
/// header fields (never from parsed rdata).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct WireRecord {
    pub(super) rtype: u16,
    pub(super) rdlength: u16,
}

/// EDNS0 OPT pseudo-record (RFC 6891): carries options such as Apple's
/// Owner option, not data about any name, so it is never a row or a
/// sighting.
pub(super) const OPT_TYPE: u16 = 41;

/// Private-use type (RFC 6895 §3.1) that out-of-scope records are
/// relabelled to before parsing, so the parser keeps their rdata as
/// opaque bytes instead of decoding it.
pub(super) const OPAQUE_TYPE: u16 = 65280;

/// Whether a parsed record is the OPT pseudo-record.
pub(super) fn is_opt(rec: &ResourceRecord<'_>, wire: Option<WireRecord>) -> bool {
    wire.map_or_else(|| u16::from(rec.rdata.type_code()), |w| w.rtype) == OPT_TYPE
}

/// Walked record headers per section, in wire order.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct WalkedSections {
    pub(super) answer: Vec<WireRecord>,
    pub(super) authority: Vec<WireRecord>,
    pub(super) additional: Vec<WireRecord>,
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
pub(super) fn walk_records(raw: &[u8]) -> Option<(Vec<u8>, WalkedSections)> {
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
    // `owner_end` is within `wire`, so these sums cannot overflow.
    let type_end = owner_end + 2;
    let class_end = type_end + 2;
    let ttl_end = class_end + 4;
    let length_end = ttl_end + 2;
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

    // The parse succeeded, so every question up to the selected one is
    // whole: skip the earlier ones (name, type, class).
    let mut offset = 12;
    for _ in 0..selected_index {
        offset = packet_name_end(wire, offset)? + 4;
    }
    let name_end = packet_name_end(wire, offset)?;
    let type_end = name_end + 2;
    let class_end = type_end + 2;
    Some(vec![
        record_field("QNAME", offset, name_end),
        record_field("QTYPE", name_end, type_end),
        record_field("QCLASS / QU", type_end, class_end),
    ])
}

pub(super) fn record_field(label: &str, start: usize, end: usize) -> RecordField {
    RecordField {
        label: label.to_string(),
        start,
        end,
    }
}

pub(super) fn whole_record_field(wire: &[u8]) -> Vec<RecordField> {
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

pub(super) fn wire_name_end(wire: &[u8], start: usize) -> Option<usize> {
    wire_name_end_with_pointers(wire, start, false)
}

pub(super) fn packet_name_end(wire: &[u8], start: usize) -> Option<usize> {
    wire_name_end_with_pointers(wire, start, true)
}

pub(super) fn wire_name_end_with_pointers(
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

pub(super) fn txt_string_fields(wire: &[u8], start: usize, end: usize) -> Vec<RecordField> {
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
pub(super) fn local_suffix_offset(trimmed: &str) -> Option<usize> {
    let off = trimmed.len().checked_sub(".local".len())?;
    // In presentation form `foo\.local` is one label, not under `.local`.
    (trimmed.as_bytes()[off..].eq_ignore_ascii_case(b".local") && !escapes_next(&trimmed[..off]))
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
pub(super) const RTYPE_NAMES: &[(u16, &str)] = &[
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
/// (`next_name. TYPE…`), and whether it names any other type. Shared by
/// address denials (app) and the inverted-bitmap finding (analyzer), so
/// both read the same rule.
pub(crate) fn nsec_address_types(rdata: &str) -> (Vec<u16>, bool) {
    let mut address = Vec::new();
    let mut other = false;
    // The next name may hold spaces (instance names do, e.g. "My A
    // Printer"), but it always ends in "." and no type mnemonic contains
    // one: the bitmap is everything after the last ". ".
    // An empty bitmap leaves the rdata ending in the name's "." (no type
    // mnemonic ends in one); only otherwise does the last ". " start it.
    let rdata = rdata.trim_end();
    let bitmap = if rdata.ends_with('.') {
        ""
    } else {
        rdata.rsplit_once(". ").map_or("", |(_, types)| types)
    };
    for t in bitmap.split_whitespace().filter_map(rtype_from_str) {
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

pub(super) fn rdata_label(data: &RData) -> String {
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
