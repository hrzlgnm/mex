// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn shared_ptr_flush_is_error() {
    let answers = vec![rec(
        "_http._tcp.local.",
        12,
        "PTR",
        "My._http._tcp.local.",
        120,
        true,
    )];
    let found = analyze_service("My", "_http._tcp.local", "", &answers);
    assert!(found
        .iter()
        .any(|a| a.kind == AnomalyKind::SharedFlush && a.severity == Severity::Error));
}

#[test]
fn enumeration_shared_flush_names_target() {
    // Enumeration rows share one owner, so the message names the
    // target: both renderers show the message verbatim there.
    let flushed = rec(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_fog._tcp.local.",
        4500,
        true,
    );
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![&flushed],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    let item = analyze(&snap)
        .iter()
        .find(|a| a.kind == AnomalyKind::SharedFlush && a.service == "enumeration")
        .expect("expected enumeration shared-flush")
        .clone();
    assert!(
        item.message.contains("_fog._tcp.local"),
        "enum finding should name its target, got: {}",
        item.message
    );
    // Service-level PTRs keep the short message: the row names them.
    let found = analyze_service(
        "X",
        "_http._tcp.local",
        "",
        &[rec(
            "_http._tcp.local.",
            12,
            "PTR",
            "X._http._tcp.local.",
            4500,
            true,
        )],
    );
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::SharedFlush)
        .expect("expected shared-flush");
    assert_eq!(item.message, "shared record with flush bit set");
}

#[test]
fn reverse_ptr_flush_is_not_an_error() {
    // Reverse-mapping PTRs are unique (one address, one owner), so the
    // flush bit is correct there. Both v4 and v6 forms stay quiet.
    for name in [
        "Android.local.37.178.168.192.in-addr.arpa.",
        "Android.local.8.A.8.E.A.F.E.F.F.F.0.A.D.B.8.3.0.0.0.0.0.0.0.0.0.0.0.0.0.0.D.F.ip6.arpa.",
    ] {
        let answers = vec![rec(name, 12, "PTR", "Android.local.", 120, true)];
        let found = analyze_service("X", "_http._tcp.local", "", &answers);
        assert!(
            !found.iter().any(|a| a.kind == AnomalyKind::SharedFlush),
            "reverse PTR {name} should be quiet"
        );
    }
}

#[test]
fn unique_missing_flush_warns_when_confirmed() {
    // Multicast answer without the bit: cache-coherency risk (Warning).
    let answers = vec![rec(
        "My._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 myhost.local.",
        120,
        false,
    )];
    let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::NoFlush)
        .expect("expected finding");
    assert_eq!(item.severity, Severity::Warning);
    assert_eq!(item.requirement, "MUST");
    // Same record via unicast reply: mex listens on 5353, so this is
    // a non-legacy response and the MUST still applies (§6.7, §10.2).
    let answers = vec![rec_with(
        "My._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 myhost.local.",
        120,
        false,
        false,
        crate::browse::RecordSection::Answer,
    )];
    let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::NoFlush)
        .expect("expected finding");
    assert_eq!(item.severity, Severity::Warning);
    assert_eq!(item.requirement, "MUST");
    assert!(
        item.message.ends_with("(unicast reply)"),
        "{}",
        item.message
    );
}

#[test]
fn missing_flush_by_section() {
    use crate::browse::RecordSection;
    let verdict = |section| {
        let answers = vec![rec_with(
            "My._http._tcp.local.",
            16,
            "TXT",
            "k=v",
            4500,
            false,
            true,
            section,
        )];
        let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::NoFlush)
            .expect("expected finding")
            .clone();
        (item.severity, item.requirement)
    };
    // Additional records in a response are held to the same MUST.
    assert_eq!(
        verdict(RecordSection::Additional),
        (Severity::Warning, "MUST")
    );
    // Known answers ride in queries and authority rows in probes: no
    // response-side MUST applies, so the absence stays informational.
    assert_eq!(verdict(RecordSection::KnownAnswer), (Severity::Info, ""));
    assert_eq!(verdict(RecordSection::Authority), (Severity::Info, ""));
}

#[test]
fn addr_records_without_flush_are_quiet() {
    // Omitting the bit on A/AAAA is universal practice, not signal.
    let answers = vec![
        rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 myhost.local.",
            120,
            true,
        ),
        rec("myhost.local.", 1, "A", "192.168.1.10", 120, false),
        rec("myhost.local.", 28, "AAAA", "fe80::1", 120, false),
    ];
    let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::NoFlush));
}
