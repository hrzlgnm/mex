// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

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

/// Labels of `wire_name(name)`, as text.
fn wire_labels_of(name: &str) -> Vec<String> {
    wire_name(name)
        .expect("encodable")
        .get_labels()
        .iter()
        .map(|label| String::from_utf8_lossy(label.as_ref()).into_owned())
        .collect()
}

#[test]
fn wire_name_keeps_escaped_dots_inside_their_label() {
    assert_eq!(
        wire_labels_of("amzn\\.dmgr:ABC._amzn-wplay._tcp.local"),
        ["amzn.dmgr:ABC", "_amzn-wplay", "_tcp", "local"]
    );
    assert_eq!(
        wire_labels_of("foo\\._tcp\\.bar._http._tcp.local."),
        ["foo._tcp.bar", "_http", "_tcp", "local"]
    );
    assert_eq!(
        wire_labels_of("back\\\\slash._x._tcp.local"),
        ["back\\slash", "_x", "_tcp", "local"]
    );
    // Without an escape, every dot separates (#386): instance `a` of
    // `b._x._tcp.local` is not instance `a.b` of `_x._tcp.local`.
    assert_eq!(
        wire_labels_of("a.b._x._tcp.local"),
        ["a", "b", "_x", "_tcp", "local"]
    );
    assert_eq!(
        wire_labels_of("_printer._sub._http._tcp.local."),
        ["_printer", "_sub", "_http", "_tcp", "local"]
    );
    assert_eq!(
        wire_labels_of("FritzBoxRepeater.fritz.box"),
        ["FritzBoxRepeater", "fritz", "box"]
    );
}

#[test]
fn dotted_instance_query_round_trips_in_presentation_form() {
    let name = "Á\\.a._test._tcp.local";
    let ev = roundtrip_query(&QueryRequest {
        name: name.to_string(),
        record_type: TYPE::SRV,
        known_answers: Vec::new(),
        qu: false,
    });
    assert_eq!(ev.questions[0].name, format!("{name}."));
    assert_eq!(
        ev.questions[0].owner_labels,
        [&b"\xc3\x81.a"[..], b"_test", b"_tcp", b"local"]
    );
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
        &[ptr_query()],
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
        &[ptr_query()],
        Family::V6,
        &[],
        &links,
        &mut failures,
        &mut copies,
    );
    assert_eq!(copies.recent.len(), 1);
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
        &[ptr_query()],
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
        &[ptr_query()],
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
        &[ptr_query()],
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
        &[ptr_query()],
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
            &[ptr_query()],
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

fn roundtrip_query(req: &QueryRequest) -> Event {
    let bytes = encode_query(req, "").expect("query must encode");
    parse_packet(&bytes, test_source(), std::net::IpAddr::V4(MDNS_V4), "", 0).unwrap()
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
fn repeat_pin_failure_still_skips_the_copy() {
    // The second failure is already on record (not logged again), but
    // the copy is still skipped: never an unpinned send.
    let eth0 = Ipv4Addr::new(192, 168, 1, 2);
    let socket = FakeSocket {
        failing_pin: Some(Egress::V4(eth0)),
        ..FakeSocket::default()
    };
    let links = [("eth0".to_string(), eth0)];
    let mut failures = SendFailures::default();
    for _ in 0..2 {
        send_on_all_interfaces(
            &socket,
            &[ptr_query()],
            Family::V4,
            &links,
            &[],
            &mut failures,
            &mut SentCopies::default(),
        );
    }
    assert_eq!(
        *socket.calls.borrow(),
        ["pin V4(192.168.1.2)", "pin V4(192.168.1.2)"]
    );
}

#[test]
fn repeat_send_failure_is_not_remembered_as_sent() {
    // Every pass still tries the send; none of the failed copies may be
    // taken for our own loopback copy later.
    let socket = FakeSocket::default();
    socket.failing_send.set(true);
    let links = [("eth0".to_string(), 2u32)];
    let mut failures = SendFailures::default();
    let mut sent = SentCopies::default();
    for _ in 0..2 {
        send_on_all_interfaces(
            &socket,
            &[ptr_query()],
            Family::V6,
            &[],
            &links,
            &mut failures,
            &mut sent,
        );
    }
    assert_eq!(
        *socket.calls.borrow(),
        [
            "pin V6(2)",
            "send [ff02::fb%2]:5353",
            "pin V6(2)",
            "send [ff02::fb%2]:5353",
        ]
    );
    let bytes = encode_query(&ptr_query(), "eth0").unwrap();
    assert!(!sent.take(&bytes, Instant::now()));
}

#[test]
fn unencodable_request_sends_nothing_after_the_pin() {
    let socket = FakeSocket::default();
    let req = QueryRequest {
        name: "a..local".to_string(),
        ..ptr_query()
    };
    let mut sent = SentCopies::default();
    send_on_all_interfaces(
        &socket,
        std::slice::from_ref(&req),
        Family::V6,
        &[],
        &[("eth0".to_string(), 2u32)],
        &mut SendFailures::default(),
        &mut sent,
    );
    assert_eq!(*socket.calls.borrow(), ["pin V6(2)"]);
    assert!(sent.recent.is_empty(), "nothing sent, nothing remembered");
}

#[test]
fn wire_name_rejects_empty_and_overlong_labels() {
    let longest = "a".repeat(63);
    let too_long = "a".repeat(64);
    assert!(wire_name("").is_none());
    assert!(wire_name("a..b.local").is_none());
    assert!(wire_name(&format!("{too_long}.local")).is_none());
    assert!(wire_name(&format!("{longest}.local")).is_some());
}

#[test]
fn encode_query_rejects_unencodable_name() {
    let req = QueryRequest {
        name: "a..local".to_string(),
        ..ptr_query()
    };
    assert!(encode_query(&req, "").is_none());
}

#[test]
fn unencodable_known_answer_is_skipped_others_kept() {
    let ka = |target: &str| KnownAnswer {
        target: target.to_string(),
        ttl: 120,
        iface: String::new(),
    };
    let req = QueryRequest {
        known_answers: vec![ka(""), ka("Good._http._tcp.local")],
        ..ptr_query()
    };
    let ev = roundtrip_query(&req);
    assert_eq!(ev.questions.len(), 1, "the question survives");
    assert_eq!(ev.query_kas.len(), 1);
    assert_eq!(ev.query_kas[0].rdata, "Good._http._tcp.local.");
}

#[test]
fn wire_name_rejects_names_over_255_octets() {
    // RFC 1035 §3.1: a whole name is at most 255 octets on the wire,
    // counting each label's length octet and the root's zero octet.
    // Four 63-octet labels encode to 4 * 64 + 1 = 257 octets.
    let label = "a".repeat(63);
    let too_long = [label.as_str(); 4].join(".");
    assert!(wire_name(&too_long).is_none());
    // 3 * 64 + (61 + 1) + 1 = 255 octets: the longest valid name.
    let longest = format!("{label}.{label}.{label}.{}", "a".repeat(61));
    assert!(wire_name(&longest).is_some());
    assert!(wire_name(&format!("{longest}a")).is_none(), "256 octets");
}

#[test]
fn query_codec_failure_is_handled_not_a_panic() {
    let qname = wire_name("_http._tcp.local").unwrap();
    assert!(build_query_into(&mut LimitedSink::new(0), &qname, TYPE::PTR, false, &[]).is_none());
    // The in-memory sink encodes as before.
    let bytes = build_query(&qname, TYPE::PTR, false, &[]).unwrap();
    let ev = parse_packet(&bytes, test_source(), std::net::IpAddr::V4(MDNS_V4), "", 0).unwrap();
    assert_eq!(ev.questions[0].name, "_http._tcp.local.");
}

fn dense_ptr_query() -> QueryRequest {
    QueryRequest {
        known_answers: (0..2000)
            .map(|i| KnownAnswer {
                target: format!("instance-{i:05}._http._tcp.local"),
                ttl: 120,
                iface: String::new(),
            })
            .collect(),
        ..ptr_query()
    }
}

#[test]
fn encode_failure_ends_the_query_at_either_build() {
    // The first build fails outright.
    assert!(encode_query_into(&mut LimitedSink::new(0), &ptr_query(), "").is_none());
    // The oversized first build fits the budget exactly; the first
    // known-answer truncation retry then fails. The budget is what the
    // build writes, not the packet length: the codec writes each
    // RDLENGTH twice (a placeholder, then the value).
    let req = dense_ptr_query();
    let qname = wire_name(&req.name).unwrap();
    let kas: Vec<_> = req
        .known_answers
        .iter()
        .map(|ka| (wire_name(&ka.target).unwrap(), ka.ttl))
        .collect();
    let mut probe = LimitedSink::new(usize::MAX);
    let first = build_query_into(&mut probe, &qname, req.record_type, req.qu, &kas).unwrap();
    assert!(first.len() > MAX_QUERY_BYTES, "the retry path is taken");
    let first_writes = usize::MAX - probe.budget;
    assert!(encode_query_into(&mut LimitedSink::new(first_writes), &req, "").is_none());
    // With room to spare, the retries succeed as before.
    assert!(encode_query_into(&mut LimitedSink::new(usize::MAX), &req, "").is_some());
}

#[test]
fn a_reused_in_memory_sink_starts_each_packet_fresh() {
    // Truncation retries reuse the sink: a packet must not carry the
    // previous one's length as leading zeros.
    let qname = wire_name("_http._tcp.local").unwrap();
    let mut sink = std::io::Cursor::new(Vec::new());
    let first = build_query_into(&mut sink, &qname, TYPE::PTR, false, &[]).unwrap();
    let second = build_query_into(&mut sink, &qname, TYPE::PTR, false, &[]).unwrap();
    assert_eq!(first, second);
}

#[test]
fn own_queries_keep_the_aa_bit_clear() {
    // RFC 6762 §18.4: mex must never raise `query-aa-bit` itself (#423).
    let mut req = ptr_query();
    assert!(!roundtrip_query(&req).is_authoritative_query());
    req.qu = true;
    req.known_answers = vec![KnownAnswer {
        target: "Inst._http._tcp.local.".into(),
        ttl: 4500,
        iface: String::new(),
    }];
    assert!(!roundtrip_query(&req).is_authoritative_query());
    let inferred = inferred_question_packet("_http._tcp.local", 12, false).unwrap();
    assert_eq!(inferred[2] & 0x04, 0);
}

#[test]
fn own_queries_keep_opcode_zero() {
    // RFC 6762 §18.3: mex must never send what it ignores (#427).
    let mut req = ptr_query();
    assert_eq!(roundtrip_query(&req).opcode(), 0);
    req.qu = true;
    req.known_answers = vec![KnownAnswer {
        target: "Inst._http._tcp.local.".into(),
        ttl: 4500,
        iface: String::new(),
    }];
    assert_eq!(roundtrip_query(&req).opcode(), 0);
    let inferred = inferred_question_packet("_http._tcp.local", 12, false).unwrap();
    assert_eq!(inferred[2] & 0x78, 0);
}

// --- #431: each copy that left is reported as our own send ---

#[test]
fn each_sent_copy_is_reported_with_its_link_family_and_question() {
    let socket = FakeSocket::default();
    let links = [("eth0".to_string(), 2u32), ("wlan0".to_string(), 3u32)];
    let before = Instant::now();
    let sent = send_on_all_interfaces(
        &socket,
        &[ptr_query()],
        Family::V6,
        &[],
        &links,
        &mut SendFailures::default(),
        &mut SentCopies::default(),
    );
    let reported: Vec<_> = sent
        .iter()
        .map(|s| (s.iface.as_str(), s.ifindex, s.v6, s.questions.clone()))
        .collect();
    let question = vec![("_http._tcp.local".to_string(), 12)];
    assert_eq!(
        reported,
        [
            ("eth0", 2, true, question.clone()),
            ("wlan0", 3, true, question)
        ]
    );
    assert!(sent
        .iter()
        .all(|s| s.sent_at >= before && s.sent_at <= Instant::now()));

    let v4 = [("eth0".to_string(), Ipv4Addr::new(192, 168, 1, 2))];
    let sent = send_on_all_interfaces(
        &socket,
        &[ptr_query()],
        Family::V4,
        &v4,
        &[],
        &mut SendFailures::default(),
        &mut SentCopies::default(),
    );
    assert_eq!(sent.len(), 1);
    assert!(!sent[0].v6);
    assert_eq!(
        sent[0].ifindex, 0,
        "pinned by address: the listener fills it in"
    );
}

#[test]
fn failed_or_unencodable_copies_are_not_reported() {
    let eth0 = Ipv4Addr::new(192, 168, 1, 2);
    let wlan0 = Ipv4Addr::new(10, 0, 0, 2);
    let links = [("eth0".to_string(), eth0), ("wlan0".to_string(), wlan0)];
    let send = |socket: &FakeSocket, req: &QueryRequest| {
        send_on_all_interfaces(
            socket,
            std::slice::from_ref(req),
            Family::V4,
            &links,
            &[],
            &mut SendFailures::default(),
            &mut SentCopies::default(),
        )
    };
    // A failed pin skips that link's copy only.
    let socket = FakeSocket {
        failing_pin: Some(Egress::V4(eth0)),
        ..FakeSocket::default()
    };
    let sent = send(&socket, &ptr_query());
    let links_sent: Vec<_> = sent.iter().map(|s| s.iface.as_str()).collect();
    assert_eq!(links_sent, ["wlan0"]);
    // A failed send reports nothing.
    let socket = FakeSocket::default();
    socket.failing_send.set(true);
    assert!(send(&socket, &ptr_query()).is_empty());
    // Nor does a request that can't be encoded.
    let req = QueryRequest {
        name: "a..local".to_string(),
        ..ptr_query()
    };
    assert!(send(&FakeSocket::default(), &req).is_empty());
}

// --- #430: questions due together share a packet ---

/// One question of `rtype` for `name`, QM, without known answers.
fn ask(name: &str, rtype: TYPE) -> QueryRequest {
    QueryRequest {
        name: name.to_string(),
        record_type: rtype,
        known_answers: Vec::new(),
        qu: false,
    }
}

/// `name` PTR with `n` known answers, all learned on `iface`.
fn ptr_with_kas(name: &str, n: usize, iface: &str) -> QueryRequest {
    QueryRequest {
        known_answers: (0..n)
            .map(|i| KnownAnswer {
                target: format!("instance-{i:05}.{name}"),
                ttl: 4500,
                iface: iface.to_string(),
            })
            .collect(),
        ..ask(name, TYPE::PTR)
    }
}

fn parse(bytes: &[u8]) -> Event {
    parse_packet(bytes, test_source(), std::net::IpAddr::V4(MDNS_V4), "", 0).unwrap()
}

#[test]
fn questions_due_together_leave_in_one_packet() {
    let batch = [
        ask("Inst._http._tcp.local", TYPE::SRV),
        ask("Inst._http._tcp.local", TYPE::TXT),
        ask("Host.local", TYPE::A),
        ask("Host.local", TYPE::AAAA),
    ];
    let packets = encode_batch(&batch, "eth0");
    assert_eq!(packets.len(), 1);
    let (bytes, asked) = &packets[0];
    assert_eq!(asked, &[0, 1, 2, 3]);
    let questions: Vec<_> = parse(bytes)
        .questions
        .iter()
        .map(|q| (q.name.clone(), q.rtype))
        .collect();
    assert_eq!(
        questions,
        [
            ("Inst._http._tcp.local.".to_string(), 33),
            ("Inst._http._tcp.local.".to_string(), 16),
            ("Host.local.".to_string(), 1),
            ("Host.local.".to_string(), 28),
        ],
        "wire case kept"
    );
}

#[test]
fn only_the_startup_question_carries_the_qu_bit() {
    let mut enumeration = ask("_services._dns-sd._udp.local", TYPE::PTR);
    enumeration.qu = true;
    let batch = [enumeration, ask("_http._tcp.local", TYPE::PTR)];
    let (bytes, _) = &encode_batch(&batch, "")[0];
    let qu: Vec<_> = parse(bytes).questions.iter().map(|q| q.qu).collect();
    assert_eq!(qu, [true, false]);
}

#[test]
fn each_ptr_question_carries_its_own_interface_scoped_known_answers() {
    let mut http = ptr_with_kas("_http._tcp.local", 2, "eth0");
    http.known_answers.push(KnownAnswer {
        target: "Elsewhere._http._tcp.local".to_string(),
        ttl: 4500,
        iface: "wlan0".to_string(),
    });
    let batch = [
        http,
        ask("Inst._http._tcp.local", TYPE::SRV),
        ptr_with_kas("_ipp._tcp.local", 1, ""),
    ];
    let (bytes, _) = &encode_batch(&batch, "eth0")[0];
    let kas: Vec<_> = parse(bytes)
        .query_kas
        .iter()
        .map(|k| (k.name.clone(), k.rdata.clone()))
        .collect();
    assert_eq!(
        kas,
        [
            (
                "_http._tcp.local.".to_string(),
                "instance-00000._http._tcp.local.".to_string()
            ),
            (
                "_http._tcp.local.".to_string(),
                "instance-00001._http._tcp.local.".to_string()
            ),
            (
                "_ipp._tcp.local.".to_string(),
                "instance-00000._ipp._tcp.local.".to_string()
            ),
        ],
        "the wlan0 answer stays off eth0"
    );
}

#[test]
fn a_batch_over_the_size_limit_splits_at_question_boundaries() {
    // Each question fits alone, but not all together.
    let batch: Vec<_> = (0..6)
        .map(|i| ptr_with_kas(&format!("_svc{i}._tcp.local"), 120, ""))
        .collect();
    let packets = encode_batch(&batch, "");
    assert!(packets.len() > 1, "{} packet(s)", packets.len());
    let mut asked: Vec<usize> = Vec::new();
    for (bytes, idx) in &packets {
        assert!(bytes.len() <= MAX_QUERY_BYTES, "{} bytes", bytes.len());
        let ev = parse(bytes);
        assert_eq!(ev.questions.len(), idx.len());
        // Whole questions: every one keeps all 120 known answers.
        assert_eq!(ev.query_kas.len(), 120 * idx.len());
        asked.extend(idx.iter().copied());
    }
    assert_eq!(asked, [0, 1, 2, 3, 4, 5], "no question lost or repeated");
}

#[test]
fn a_question_too_large_alone_sheds_known_answers_in_its_own_packet() {
    let batch = [
        ask("Inst._http._tcp.local", TYPE::SRV),
        dense_ptr_query(),
        ask("Inst._http._tcp.local", TYPE::TXT),
    ];
    let packets = encode_batch(&batch, "");
    let asked: Vec<_> = packets.iter().map(|(_, idx)| idx.clone()).collect();
    assert_eq!(asked, [vec![0], vec![1], vec![2]]);
    let (bytes, _) = &packets[1];
    assert!(bytes.len() <= MAX_QUERY_BYTES);
    let ev = parse(bytes);
    assert_eq!(ev.questions.len(), 1, "the question is kept");
    assert!(!ev.query_kas.is_empty() && ev.query_kas.len() < 2000);
}

#[test]
fn an_unencodable_question_is_skipped_and_the_rest_sent() {
    let batch = [
        ask("Inst._http._tcp.local", TYPE::SRV),
        ask("a..local", TYPE::A),
        ask("Host.local", TYPE::A),
    ];
    let packets = encode_batch(&batch, "");
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].1, [0, 2]);
    assert_eq!(parse(&packets[0].0).questions.len(), 2);
}

#[test]
fn a_codec_failure_ends_the_batch_without_a_panic() {
    let batch = [
        ask("Inst._http._tcp.local", TYPE::SRV),
        ask("Host.local", TYPE::A),
    ];
    assert!(encode_batch_into(&mut LimitedSink::new(0), &batch, "").is_empty());
    // A budget for the first packet only: the second build fails, and the
    // packet encoded before it is kept.
    let mut probe = LimitedSink::new(usize::MAX);
    encode_batch_into(&mut probe, &batch[..1], "");
    let first_writes = usize::MAX - probe.budget;
    let packets = encode_batch_into(&mut LimitedSink::new(first_writes), &batch, "");
    assert_eq!(packets.len(), 1);
    assert_eq!(packets[0].1, [0]);
    // An oversized question whose shedding retry fails is dropped too.
    let big = [dense_ptr_query()];
    let mut probe = LimitedSink::new(usize::MAX);
    let req = &big[0];
    let qname = wire_name(&req.name).unwrap();
    let kas: Vec<_> = req
        .known_answers
        .iter()
        .map(|ka| (wire_name(&ka.target).unwrap(), ka.ttl))
        .collect();
    build_query_into(&mut probe, &qname, req.record_type, req.qu, &kas).unwrap();
    let alone_writes = usize::MAX - probe.budget;
    // Room for the first full build twice (the trial and the alone
    // build), then the shedding retry runs out.
    assert!(encode_batch_into(&mut LimitedSink::new(2 * alone_writes), &big, "").is_empty());
}

#[test]
fn every_packet_of_a_batch_leaves_on_every_link() {
    // Two packets (the batch splits) on two links: each pinned once,
    // every copy remembered and reported with its own questions.
    let socket = FakeSocket::default();
    let links = [("eth0".to_string(), 2u32), ("wlan0".to_string(), 3u32)];
    let batch: Vec<_> = (0..6)
        .map(|i| ptr_with_kas(&format!("_svc{i}._tcp.local"), 120, ""))
        .collect();
    let per_link = encode_batch(&batch, "eth0").len();
    assert!(per_link > 1);
    let mut copies = SentCopies::default();
    let sent = send_on_all_interfaces(
        &socket,
        &batch,
        Family::V6,
        &[],
        &links,
        &mut SendFailures::default(),
        &mut copies,
    );
    let calls = socket.calls.borrow();
    let pins: Vec<_> = calls.iter().filter(|c| c.starts_with("pin")).collect();
    assert_eq!(pins, ["pin V6(2)", "pin V6(3)"]);
    assert_eq!(calls.len(), 2 + 2 * per_link);
    assert_eq!(sent.len(), 2 * per_link);
    assert_eq!(copies.recent.len(), 2 * per_link);
    let eth0_questions: usize = sent
        .iter()
        .filter(|s| s.iface == "eth0")
        .map(|s| s.questions.len())
        .sum();
    assert_eq!(eth0_questions, 6, "every question reported once per link");
}
