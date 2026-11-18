// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn reverse_service_type_is_not_a_type_format() {
    // Reverse-mapping names map addresses to hostnames; they are not
    // service types, so a reverse-named service must stay quiet even
    // if one ever reaches the analyzer.
    let found = analyze_service("Android", "local.37.178.168.192.in-addr.arpa", "", &[]);
    assert!(
        !found.iter().any(|a| a.kind == AnomalyKind::TypeFormat),
        "reverse name must not flag, got: {found:?}"
    );
}

#[test]
fn type_format_flags_bad_shape() {
    let answers = vec![];
    let found = analyze_service("X", "http.tcp.local", "", &answers);
    assert!(found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
}

#[test]
fn type_format_rejects_bad_labels() {
    for t in [
        "_80._tcp.local",
        "_-bad._tcp.local",
        "_bad-._tcp.local",
        "_http._sctp.local",
    ] {
        let found = analyze_service("X", t, "", &[]);
        assert!(
            found.iter().any(|a| a.kind == AnomalyKind::TypeFormat),
            "type {t} should be flagged"
        );
    }
}

#[test]
fn type_format_accepts_valid_subtype_label() {
    let subtypes = vec![b"_printer".to_vec()];
    let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &subtypes);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
}

#[test]
fn type_format_accepts_subtype_with_arbitrary_octets() {
    let subtypes = vec![b"uuid%group\xff".to_vec()];
    let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &subtypes);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
}

#[test]
fn type_format_accepts_63_byte_subtype_and_rejects_longer_label() {
    let accepted = vec![b'x'; 63];
    let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &[accepted]);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));

    let rejected = vec![b'x'; 64];
    let found = analyze_service_sub("X", "_http._tcp.local", "", &[], &[rejected]);
    assert!(found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
}

#[test]
fn type_format_accepts_tcp_udp_and_enum() {
    for t in [
        "_http._tcp.local",
        "_printer._udp.local",
        "_services._dns-sd._udp.local",
    ] {
        let found = analyze_service("X", t, "", &[]);
        assert!(
            !found.iter().any(|a| a.kind == AnomalyKind::TypeFormat),
            "type {t} should be quiet"
        );
    }
}

#[test]
fn type_format_ignores_label_length_and_underscores() {
    // Neither the RFC's 15-character limit nor inner underscores are
    // enforced by real stacks, so the SHIELD's real type stays quiet.
    let found = analyze_service("SHIELD", "_nv_shield_remote._tcp.local", "", &[]);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
}

#[test]
fn enumeration_subtype_target_flags_new_kind() {
    let subtype = rec(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_T35._sub._matterd._udp.local.",
        4500,
        false,
    );
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![&subtype],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    let found = analyze(&snap);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::EnumSubtype)
        .expect("expected enum-subtype");
    assert_eq!(item.severity, Severity::Warning);
    // The message names the subtype: enumeration rows all share one
    // scope, so the target tells identical rows apart.
    assert!(
        item.message.contains("_T35._sub._matterd._udp.local"),
        "message should name the subtype, got: {}",
        item.message
    );
    // Valid subtype: no naming-shape finding alongside.
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
    let base = rec(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_http._tcp.local.",
        4500,
        false,
    );
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![&base],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    assert!(
        !analyze(&snap)
            .iter()
            .any(|a| a.kind == AnomalyKind::EnumSubtype),
        "base types stay quiet"
    );
}

#[test]
fn enumeration_ptr_with_bad_type_flags_row() {
    let enum_rec = rec(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_80._tcp.local.",
        4500,
        false,
    );
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![&enum_rec],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    let found = analyze(&snap);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::TypeFormat && a.service == "enumeration")
        .expect("expected enumeration type-format");
    // Full record identity so the Answers table can mark the PTR row.
    assert_eq!(
        item.record_name.as_deref(),
        Some("_services._dns-sd._udp.local.")
    );
    assert_eq!(item.rtype, Some(12));
    assert!(item.rdata.is_some());
}

#[test]
fn enumeration_ptr_with_good_type_stays_quiet() {
    let enum_rec = rec(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_http._tcp.local.",
        4500,
        false,
    );
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![&enum_rec],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    assert!(!analyze(&snap)
        .iter()
        .any(|a| a.kind == AnomalyKind::TypeFormat));
}

#[test]
fn enumeration_subtype_validates_raw_octets_not_lossy_display() {
    let label: &'static [u8] = Box::leak(b"uuid.\xff".to_vec().into_boxed_slice());
    let labels: &'static [simple_dns::Label<'static>] = Box::leak(
        vec![
            simple_dns::Label::new_unchecked(label),
            simple_dns::Label::new_unchecked(&b"_sub"[..]),
            simple_dns::Label::new_unchecked(&b"_http"[..]),
            simple_dns::Label::new_unchecked(&b"_tcp"[..]),
            simple_dns::Label::new_unchecked(&b"local"[..]),
        ]
        .into_boxed_slice(),
    );
    let mut packet = simple_dns::Packet::new_reply(0);
    packet.answers.push(simple_dns::ResourceRecord::new(
        simple_dns::Name::new_unchecked("_services._dns-sd._udp.local."),
        simple_dns::CLASS::IN,
        4500,
        simple_dns::rdata::RData::PTR(simple_dns::Name::new_with_labels(labels).into()),
    ));
    let bytes = packet.build_bytes_vec().unwrap();
    let event = crate::browse::parse_packet(
        &bytes,
        test_source(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251)),
        "br0",
        3,
    )
    .unwrap();
    let subtype = &event.answers[0];
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![subtype],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };

    let found = analyze(&snap);
    assert!(found.iter().any(|a| a.kind == AnomalyKind::EnumSubtype));
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TypeFormat));
    assert!(found
        .iter()
        .find(|a| a.kind == AnomalyKind::EnumSubtype)
        .unwrap()
        .message
        .contains(r"uuid\x2E\xFF._sub._http._tcp.local"));
}

#[test]
fn enumeration_ptr_with_valid_subtype_stays_quiet() {
    let enum_rec = rec(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_printer._sub._http._tcp.local.",
        4500,
        false,
    );
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![&enum_rec],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    assert!(!analyze(&snap)
        .iter()
        .any(|a| a.kind == AnomalyKind::TypeFormat));
}

#[test]
fn enumeration_ptr_with_overlong_subtype_flags_row() {
    let target = format!("{}._sub._http._tcp.local.", "x".repeat(64));
    let enum_rec = rec(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        &target,
        4500,
        false,
    );
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![&enum_rec],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    assert!(analyze(&snap)
        .iter()
        .any(|a| a.kind == AnomalyKind::TypeFormat && a.service == "enumeration"));
}
