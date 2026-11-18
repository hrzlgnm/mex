// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn unicast_style_verdict_by_type_section_and_domain() {
    use super::unicast_style_verdict as v;
    use crate::browse::RecordSection::*;
    let sev = |rtype, section, mdns| v(rtype, section, mdns).map(|(s, _, rfc, _)| (s, rfc));
    // ANY is never an RR type, wherever it sits.
    assert_eq!(
        sev(255, Answer, true),
        Some((Severity::Error, "RFC 1035 §3.2.3"))
    );
    // SOA in Authority is a unicast-style negative answer (§6.1 NSEC),
    // whatever the owner domain.
    for mdns in [true, false] {
        assert_eq!(
            sev(6, Authority, mdns),
            Some((Severity::Warning, "RFC 6762 §6.1"))
        );
    }
    // SOA as an answer: none exist in mDNS zones; real data elsewhere.
    assert_eq!(
        sev(6, Answer, true),
        Some((Severity::Warning, "RFC 6762 §12"))
    );
    assert_eq!(sev(6, Answer, false), Some((Severity::Info, "RFC 6762 §3")));
    // Known answers ride in queries: never above Info.
    assert_eq!(
        sev(255, KnownAnswer, true).map(|(s, _)| s),
        Some(Severity::Info)
    );
    // No requirement level is ever claimed.
    assert!([6, 255]
        .into_iter()
        .all(|t| v(t, Authority, true).is_some_and(|(_, _, _, req)| req.is_empty())));
    // In-scope types (NS included) and other out-of-scope types
    // (MX: `unsupported_type_verdict`) get no unicast-style verdict.
    for rtype in [1, 2, 5, 12, 13, 15, 16, 28, 33, 47] {
        assert_eq!(v(rtype, Answer, true), None, "type {rtype}");
    }
}

#[test]
fn unsupported_type_verdict_covers_only_the_rest() {
    use super::unsupported_type_verdict as v;
    use crate::browse::RecordSection::*;
    for rtype in [1, 2, 5, 6, 12, 13, 16, 28, 33, 47, 255] {
        assert_eq!(v(rtype, Answer), None, "type {rtype}");
    }
    assert_eq!(v(15, Answer), Some(Severity::Warning));
    assert_eq!(v(65, Additional), Some(Severity::Warning));
    assert_eq!(v(15, KnownAnswer), Some(Severity::Info));
}

#[test]
fn non_utf8_name_is_warning_with_rfc_ref() {
    let mut bad = rec(
        "Test._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 myhost.local.",
        120,
        true,
    );
    bad.invalid_utf8 = true;
    let found = analyze_service("Test", "_http._tcp.local", "myhost.local.", &[bad])
        .into_iter()
        .find(|a| a.kind == AnomalyKind::NonUtf8)
        .expect("expected non-utf8-name");
    assert_eq!(found.severity, Severity::Warning);
    assert_eq!(found.rfc, "RFC 6762 §16");
    assert_eq!(found.requirement, "MUST NOT");
    // A clean row with the same shape stays quiet for this kind.
    let clean = vec![rec(
        "Test._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 myhost.local.",
        120,
        true,
    )];
    let found = analyze_service("Test", "_http._tcp.local", "myhost.local.", &clean);
    assert!(found.iter().all(|a| a.kind != AnomalyKind::NonUtf8));
}

#[test]
fn unicast_question_flags_soa_with_querier() {
    let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, querier)]);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
        .expect("expected SOA question finding");
    // RFC 6762 §3 requires .local queries on multicast: asking is
    // compliant, the record just cannot exist (§12).
    assert_eq!(item.severity, Severity::Info);
    assert_eq!((item.rfc, item.requirement), ("RFC 6762 §12", ""));
    assert_eq!(item.service, "My._http._tcp.local");
    assert_eq!(item.record_name.as_deref(), Some("fritz.box."));
    assert_eq!(item.rtype, Some(6));
    assert_eq!(
        item.source.as_deref(),
        Some("192.168.1.9:5353"),
        "finding should name the querier, got: {:?}",
        item.source
    );
}

#[test]
fn unicast_question_marks_one_shot_querier() {
    // A stub resolver asking from an ephemeral port (§5.1) reads
    // differently than a full mDNS stack on 5353.
    let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
    let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, stub)]);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
        .expect("expected SOA unicast question");
    assert!(
        item.message.contains("one-shot"),
        "stub resolver should be tagged, got: {}",
        item.message
    );
    let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, test_source())]);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
        .expect("expected SOA unicast question");
    assert!(
        !item.message.contains("one-shot"),
        "compliant querier stays untagged, got: {}",
        item.message
    );
    // Well-known ports are no defined mDNS querier either: leave the
    // finding untagged rather than guessing.
    let dns: SocketAddr = "192.168.1.9:53".parse().unwrap();
    let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, dns)]);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
        .expect("expected SOA unicast question");
    assert!(
        !item.message.contains("one-shot"),
        "well-known port stays untagged, got: {}",
        item.message
    );
    // Registered-range ports are not full 5353 queriers either, so
    // they read as one-shot by design.
    let other: SocketAddr = "192.168.1.9:5354".parse().unwrap();
    let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, other)]);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
        .expect("expected SOA unicast question");
    assert!(
        item.message.contains("one-shot"),
        "non-5353 port reads as one-shot, got: {}",
        item.message
    );
}

#[test]
fn unsupported_question_mx_and_nsec_are_info() {
    // MX is outside mex's mDNS scope; NSEC is answer-only (responders
    // send it unasked as a negative answer, RFC 6762 §6.1).
    for rtype in [15, 47] {
        let found = analyze_questions(&[qview(
            "My._http._tcp.local",
            "mail.local.",
            rtype,
            test_source(),
        )]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .unwrap_or_else(|| panic!("expected a finding for type {rtype}"));
        assert_eq!(item.severity, Severity::Info);
        assert_eq!(item.rfc, "RFC 6763 §12");
    }
}

#[test]
fn questions_for_global_names_are_not_flagged_as_such() {
    // Resolving a global SRV target over mDNS is ordinary DNS-SD: an
    // A query for fritz.box stays quiet.
    let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 1, test_source())]);
    assert!(found.is_empty(), "got: {found:?}");
    // SOA for it only flags the unicast-only type.
    let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
    let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, stub)]);
    let kinds: Vec<_> = found.iter().map(|a| a.kind.as_str()).collect();
    assert_eq!(kinds, ["unsupported-question"]);
    assert!(found[0].message.ends_with("(one-shot querier)"));
}

#[test]
fn mdns_domains_cover_local_and_link_local_reverse_zones() {
    for name in [
        "host.local.",
        "HOST.LOCAL",
        "local.",
        "_http._tcp.local.",
        "10.1.254.169.in-addr.arpa.",
        "1.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.0.8.e.f.ip6.arpa.",
        "b.e.f.ip6.arpa.",
    ] {
        assert!(is_mdns_domain(name), "{name} is an mDNS domain");
    }
    // Lookalikes outside the zones are global.
    for name in ["notlocal.", "10.1.168.192.in-addr.arpa.", "c.e.f.ip6.arpa."] {
        assert!(!is_mdns_domain(name), "{name} is not an mDNS domain");
    }
}

#[test]
fn unicast_question_self_and_per_querier() {
    let zelf: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let found = analyze_questions(&[qview("My._http._tcp.local", "host.local.", 6, zelf)]);
    assert!(found.is_empty(), "own sends stay quiet, got: {found:?}");
    let a: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let b: SocketAddr = "192.168.1.10:5353".parse().unwrap();
    let found = analyze_questions(&[
        qview("My._http._tcp.local", "host.local.", 6, a),
        qview("My._http._tcp.local", "host.local.", 6, a),
        qview("My._http._tcp.local", "host.local.", 6, b),
    ]);
    assert_eq!(
        found
            .iter()
            .filter(|f| f.kind == AnomalyKind::UnsupportedQuestion)
            .count(),
        2,
        "one finding per querier"
    );
    assert!(found.iter().all(|f| f.kind.is_question()));
}

#[test]
fn question_findings_dedup_names_case_insensitively() {
    let found = analyze_questions(&[
        qview("My._http._tcp.local", "fritz.box.", 6, test_source()),
        qview("My._http._tcp.local", "FRITZ.Box", 6, test_source()),
    ]);
    assert_eq!(
        found
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .count(),
        1,
        "unicast-question must not split on name case, got: {found:?}"
    );
}

#[test]
fn unicast_question_self_port_zero_excluded() {
    // Port 0 can never be a real mDNS querier: our own inferred sends
    // (SELF_SOURCE) must never flag.
    let zelf: SocketAddr = "0.0.0.0:0".parse().unwrap();
    let found = analyze_questions(&[qview("My._http._tcp.local", "fritz.box.", 6, zelf)]);
    assert!(
        !found
            .iter()
            .any(|a| a.kind == AnomalyKind::UnsupportedQuestion),
        "self sends must stay quiet"
    );
}

#[test]
fn unicast_question_quiet_for_multicast_types() {
    let found = analyze_questions(&[qview(
        "My._http._tcp.local",
        "_http._tcp.local.",
        12,
        test_source(),
    )]);
    assert!(
        !found
            .iter()
            .any(|a| a.kind == AnomalyKind::UnsupportedQuestion),
        "multicast-type questions must stay quiet"
    );
}

#[test]
fn unicast_question_dedups_per_querier() {
    let a: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let b: SocketAddr = "192.168.1.10:5353".parse().unwrap();
    // Same querier asking twice: one finding.
    let found = analyze_questions(&[
        qview("My._http._tcp.local", "fritz.box.", 6, a),
        qview("My._http._tcp.local", "fritz.box.", 6, a),
    ]);
    assert_eq!(
        found
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .count(),
        1
    );
    // Two queriers: one finding each, so every row can mark.
    let found = analyze_questions(&[
        qview("My._http._tcp.local", "fritz.box.", 6, a),
        qview("My._http._tcp.local", "fritz.box.", 6, b),
    ]);
    assert_eq!(
        found
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnsupportedQuestion)
            .count(),
        2
    );
}

#[test]
fn in_scope_questions_are_quiet_soa_is_info() {
    // NS and HINFO are in scope; ANY questions are ownership probes
    // (RFC 6762 §8.1, §6.1). None of them is flagged.
    for rtype in [1, 2, 5, 12, 13, 16, 28, 33, 255] {
        let found = analyze_questions(&[qview(
            "My._http._tcp.local",
            "host.local.",
            rtype,
            test_source(),
        )]);
        assert!(
            !found
                .iter()
                .any(|a| a.kind == AnomalyKind::UnsupportedQuestion),
            "type {rtype} must stay quiet"
        );
    }
    // SOA questions can never be answered in mDNS (§12).
    let found = analyze_questions(&[qview(
        "My._http._tcp.local",
        "host.local.",
        6,
        test_source(),
    )]);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnsupportedQuestion)
        .expect("expected SOA question finding");
    assert_eq!(item.severity, Severity::Info);
    assert_eq!(item.rfc, "RFC 6762 §12");
    assert_eq!(item.rtype_str.as_deref(), Some("TYPE6"));
}

fn qview(service: &str, name: &str, rtype: u16, source: SocketAddr) -> QuestionView<'static> {
    // Leak the service id for the snapshot lifetime: tests only.
    let service: &'static str = Box::leak(service.to_string().into_boxed_str());
    let rtype_str: &'static str = Box::leak(crate::browse::rtype_label(rtype).into_boxed_str());
    let name: &'static str = Box::leak(name.to_string().into_boxed_str());
    QuestionView {
        service: service.to_string(),
        name,
        rtype,
        rtype_str,
        source,
        source_label: source.to_string(),
    }
}

fn analyze_questions(questions: &[QuestionView]) -> Vec<Anomaly> {
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: Vec::new(),
        pending_hosts: HashSet::new(),
        questions: questions.to_vec(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    analyze(&snap)
}
