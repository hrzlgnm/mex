// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn ptr_with_short_base_ttl_is_flagged() {
    for ttl in [60, 120] {
        let answers = vec![rec(
            "_http._tcp.local.",
            12,
            "PTR",
            "X._http._tcp.local.",
            ttl,
            false,
        )];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::TtlMismatch)
            .unwrap_or_else(|| panic!("PTR@{ttl} should be flagged"));
        assert_eq!(item.severity, Severity::Info);
    }
}

#[test]
fn enumeration_ttl_mismatch_names_type_and_source() {
    let enum_rec = rec(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_http._tcp.local.",
        120,
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
    let item = analyze(&snap)
        .iter()
        .find(|a| a.kind == AnomalyKind::TtlMismatch)
        .expect("expected enumeration ttl-mismatch")
        .clone();
    assert_eq!(
        item.rdata.as_deref(),
        Some("_http._tcp.local."),
        "finding should point at the enumerated type, got: {:?}",
        item.rdata
    );
    assert_eq!(
        item.source.as_deref(),
        Some("192.168.1.2:5353"),
        "finding should name the announcer, got: {:?}",
        item.source
    );
}

#[test]
fn ptr_with_4500_base_is_quiet() {
    let answers = vec![rec(
        "_http._tcp.local.",
        12,
        "PTR",
        "X._http._tcp.local.",
        4500,
        false,
    )];
    let found = analyze_service("X", "_http._tcp.local", "", &answers);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TtlMismatch));
}

#[test]
fn reverse_ptr_with_120_base_is_quiet() {
    // Reverse-mapping PTRs are unique with a 120s base, not the 4500s
    // service PTR convention, so they must not flag ttl-mismatch.
    for name in [
        "1.0.0.127.in-addr.arpa.",
        "2.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.b.d.0.1.0.0.2.ip6.arpa.",
    ] {
        let answers = vec![rec(name, 12, "PTR", "myhost.local.", 120, true)];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        assert!(
            !found.iter().any(|a| a.kind == AnomalyKind::TtlMismatch),
            "reverse PTR {name} at 120s should be quiet"
        );
    }
}

#[test]
fn srv_with_120_base_is_quiet() {
    // 120s is the normal SRV base; the 4500 expectation is PTR-only.
    let answers = vec![rec(
        "X._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 myhost.local.",
        120,
        true,
    )];
    let found = analyze_service("X", "_http._tcp.local", "myhost.local.", &answers);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TtlMismatch));
}

#[test]
fn ttl_band_keeps_120_and_4500_quiet() {
    let answers = vec![
        rec("a.local.", 1, "A", "192.168.1.1", 120, true),
        rec(
            "_http._tcp.local.",
            12,
            "PTR",
            "X._http._tcp.local.",
            4500,
            false,
        ),
        rec("X._http._tcp.local.", 16, "TXT", "k=v", 4500, true),
    ];
    let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
    assert!(!found
        .iter()
        .any(|a| a.kind == AnomalyKind::TtlLow || a.kind == AnomalyKind::TtlHigh));
}

#[test]
fn ttl_extremes_flagged() {
    let answers = vec![
        rec("a.local.", 1, "A", "192.168.1.1", 5, true),
        rec("b.local.", 28, "AAAA", "fe80::1", 20000, true),
    ];
    let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
    assert!(found.iter().any(|a| a.kind == AnomalyKind::TtlLow));
    assert!(found.iter().any(|a| a.kind == AnomalyKind::TtlHigh));
}

#[test]
fn ttl_unstable_flags_mixed_bases() {
    let mut r1 = rec("a.local.", 1, "A", "192.168.1.1", 120, true);
    let mut r2 = rec("a.local.", 1, "A", "192.168.1.2", 4500, true);
    // Distinct rdata keeps both live; distinct TTL bases are the signal.
    let _ = (&mut r1, &mut r2);
    let answers = vec![r1, r2];
    let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
    assert!(found.iter().any(|a| a.kind == AnomalyKind::TtlUnstable));
}

#[test]
fn reverse_ptr_ttl_wants_host_name_base() {
    // RFC 6762 §10: reverse mapping PTRs carry a host name in rdata,
    // so their recommended TTL is 120 s, not 4500 s.
    let answers = vec![rec(
        "10.1.168.192.in-addr.arpa.",
        12,
        "PTR",
        "host.local.",
        7300,
        true,
    )];
    let found = analyze_service("X", "_http._tcp.local", "", &answers);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::TtlHigh)
        .expect("ttl-high");
    assert_eq!(item.message, "TTL 7300s, want ~120s");
}
