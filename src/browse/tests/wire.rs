// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

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
    let ev = parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3).unwrap();
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
    assert!(parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3).is_none());
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
    let ev = parse_packet(&raw, test_source(), std::net::IpAddr::V4(MDNS_V4), "br0", 3).unwrap();
    assert_eq!(ev.answers[0].rdata, "host.local. A TXT");
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

fn known_answer<'a>(owner: &'a str, target: &'a str, ttl: u32) -> ResourceRecord<'a> {
    ResourceRecord::new(
        simple_dns::Name::new_unchecked(owner),
        CLASS::IN,
        ttl,
        RData::PTR(simple_dns::Name::new_unchecked(target).into()),
    )
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

/// Wire bytes of one `a.local` record of `rtype` whose RDATA is the name
/// `b.local`, with `rdlength` written as given.
fn name_record_wire(rtype: u16, rdlength: u16) -> Vec<u8> {
    let name = |first: u8| [&[1, first][..], &[5][..], b"local", &[0][..]].concat();
    let mut wire = name(b'a');
    wire.extend_from_slice(&rtype.to_be_bytes());
    wire.extend_from_slice(&1u16.to_be_bytes()); // IN
    wire.extend_from_slice(&120u32.to_be_bytes());
    wire.extend_from_slice(&rdlength.to_be_bytes());
    wire.extend(name(b'b'));
    wire
}

#[test]
fn ns_and_cname_targets_get_their_own_field() {
    // 9-byte owner, 10 bytes of type/class/TTL/length, 9-byte target.
    for (rtype, label) in [(2, "Name server"), (5, "Canonical name")] {
        let fields = record_fields(&name_record_wire(rtype, 9), rtype);
        let target = fields.last().expect("fields");
        assert_eq!(
            (target.label.as_str(), target.start, target.end),
            (label, 19, 28),
            "rtype {rtype}"
        );
    }
}

#[test]
fn inconsistent_record_wire_is_one_whole_field() {
    let whole = |wire: &[u8]| {
        let fields = record_fields(wire, 5);
        assert_eq!(fields.len(), 1, "got {fields:?}");
        assert_eq!(
            (fields[0].label.as_str(), fields[0].start, fields[0].end),
            ("Record", 0, wire.len())
        );
    };
    // RDATA length disagrees with the bytes present.
    whole(&name_record_wire(5, 8));
    // Header cut off after the owner name and type.
    whole(&name_record_wire(5, 9)[..11]);
    // Owner name never terminates.
    whole(&[3, b'a', b'b']);
    assert!(record_fields(&[], 5).is_empty(), "nothing to show");
}
