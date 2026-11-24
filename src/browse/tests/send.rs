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
        &ptr_query(),
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
        &ptr_query(),
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
        &ptr_query(),
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
        &ptr_query(),
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
        &ptr_query(),
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
        &ptr_query(),
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
            &ptr_query(),
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
            &ptr_query(),
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
            &ptr_query(),
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
        &req,
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
    assert!(build_query_into(FailingSink, &qname, TYPE::PTR, false, &[]).is_none());
    // The in-memory sink encodes as before.
    let bytes = build_query(&qname, TYPE::PTR, false, &[]).unwrap();
    let ev = parse_packet(&bytes, test_source(), std::net::IpAddr::V4(MDNS_V4), "", 0).unwrap();
    assert_eq!(ev.questions[0].name, "_http._tcp.local.");
}
