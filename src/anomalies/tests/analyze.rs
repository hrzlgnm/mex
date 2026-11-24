// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn findings_cite_the_rfc_text_that_covers_them() {
    let answers = vec![
        rec("host.local.", 6, "SOA", "a b 1 2 3 4 5", 4500, false),
        rec("host.local.", 255, "ANY", "", 120, false),
        rec(
            "My._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 host.local.",
            3,
            false,
        ),
        rec(
            "My._http._tcp.local.",
            16,
            "TXT",
            &"k=v".repeat(500),
            4500,
            true,
        ),
    ];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    let cite = |kind: AnomalyKind, rtype: u16| {
        found
            .iter()
            .find(|a| a.kind == kind && a.rtype == Some(rtype))
            .map(|a| (a.rfc, a.requirement))
            .unwrap_or_else(|| panic!("missing {kind} for type {rtype}"))
    };
    // §12 states NS/SOA don't exist in mDNS without a 2119 keyword.
    assert_eq!(
        cite(AnomalyKind::UnicastStyleResponse, 6),
        ("RFC 6762 §12", "")
    );
    // ANY is a QTYPE, never an RR type; RFC 1035 has no 2119 keyword.
    assert_eq!(
        cite(AnomalyKind::UnicastStyleResponse, 255),
        ("RFC 1035 §3.2.3", "")
    );
    // §10.2: the host MUST set the flush bit on unique RRSet members.
    assert_eq!(cite(AnomalyKind::NoFlush, 33), ("RFC 6762 §10.2", "MUST"));
    // TTL recommendations live in §10, not §5.2 query scheduling.
    assert_eq!(cite(AnomalyKind::TtlLow, 33), ("RFC 6762 §10", "SHOULD"));
    // TXT > 1300 bytes is NOT RECOMMENDED (RFC 6763 §6.2).
    assert_eq!(
        cite(AnomalyKind::TxtOversize, 16),
        ("RFC 6763 §6.2", "SHOULD NOT")
    );
}

#[test]
fn goodbye_and_expired_never_flagged() {
    let mut gone = rec("a.local.", 1, "A", "192.168.1.1", 0, false);
    let _ = &mut gone;
    let old = aged(rec("b.local.", 28, "AAAA", "fe80::1", 120, true), 500);
    let answers = vec![gone, old];
    let found = analyze_service("X", "_http._tcp.local", "a.local.", &answers);
    assert!(
        found.is_empty()
            || !found
                .iter()
                .any(|a| a.kind == AnomalyKind::UnicastStyleResponse
                    || a.kind == AnomalyKind::TtlLow)
    );
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TtlHigh));
}

#[test]
fn kinds_display_and_order_by_their_label() {
    use AnomalyKind::*;
    assert_eq!(SharedFlush.to_string(), SharedFlush.as_str());
    assert_eq!(format!("{ConflictingAnswers}"), "conflicting-answers");
    // Ordered by label, so sorted findings group by kind name.
    assert!(ConflictingAnswers < SharedFlush);
    assert_eq!(
        ConflictingAnswers.partial_cmp(&ConflictingAnswers),
        Some(std::cmp::Ordering::Equal)
    );
}

#[test]
fn goodbye_sightings_and_enumeration_rows_are_not_checked() {
    // A flushed shared PTR is an error while live; once it says goodbye
    // (TTL 0) it is no longer held against its owner.
    let ptr = |ttl| {
        rec(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_fog._tcp.local.",
            ttl,
            true,
        )
    };
    let flagged = |enum_answer: &RawRecord, sighting: &RawRecord| {
        let snap = Snapshot {
            services: Vec::new(),
            enum_answers: vec![enum_answer],
            pending_hosts: HashSet::new(),
            questions: Vec::new(),
            sightings: vec![("X._http._tcp.local".to_string(), sighting)],
            host_addresses: Vec::new(),
            device_names: HashMap::new(),
        };
        let mut owners: Vec<String> = analyze(&snap)
            .into_iter()
            .filter(|a| a.kind == AnomalyKind::SharedFlush)
            .map(|a| a.service)
            .collect();
        owners.sort();
        owners
    };
    let (live, gone) = (ptr(4500), ptr(0));
    assert_eq!(flagged(&live, &live), ["X._http._tcp.local", "enumeration"]);
    assert!(flagged(&gone, &gone).is_empty());
}
