use super::*;

#[test]
fn unicast_style_response_soa_for_global_name_is_info() {
    // A router answering a query for its own unicast zone over mDNS:
    // §12 does not cover fritz.box, so this is an observation only.
    let answers = vec![
        rec("fritz.box.", 2, "NS", "fritz.box.", 10, false),
        rec("fritz.box.", 6, "TYPE6", "rdlength=49", 10, false),
    ];
    let found = analyze_service("Fritzel", "_fbox._tcp.local", "fritz.box.", &answers);
    let found_rows: Vec<_> = found
        .iter()
        .filter(|a| a.kind == AnomalyKind::UnicastStyleResponse)
        .collect();
    assert_eq!(found_rows.len(), 1);
    for item in found_rows {
        assert_eq!(item.rtype, Some(6));
        assert_eq!(item.severity, Severity::Info);
        assert_eq!(item.rfc, "RFC 6762 §3");
        assert_eq!(item.requirement, "");
        assert!(
            item.message.contains("in Answer section"),
            "{}",
            item.message
        );
    }
    // The same SOA owned by a .local name: mDNS zones have none (§12).
    let answers = vec![rec("host.local.", 6, "TYPE6", "rdlength=22", 120, false)];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnicastStyleResponse)
        .expect("expected SOA unicast-style response");
    assert_eq!(item.severity, Severity::Warning);
    assert_eq!(item.rfc, "RFC 6762 §12");
}

#[test]
fn unicast_style_response_flags_any_as_error() {
    let answers = vec![rec("host.local.", 255, "ANY", "", 120, false)];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnicastStyleResponse)
        .expect("expected ANY unicast-style response");
    assert_eq!(item.severity, Severity::Error);
}

#[test]
fn enumeration_soa_response_names_service_and_source() {
    let enum_rec = rec(
        "_services._dns-sd._udp.local.",
        6,
        "SOA",
        "host.local. admin 1794425867 21600 1800 43200 10",
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
        .find(|a| a.kind == AnomalyKind::UnicastStyleResponse)
        .expect("expected enumeration SOA unicast-style response")
        .clone();
    assert_eq!(item.service, "enumeration");
    assert_eq!(item.severity, Severity::Warning);
    assert_eq!(
        item.source.as_deref(),
        Some("192.168.1.2:5353"),
        "finding should name the announcer, got: {:?}",
        item.source
    );
}

#[test]
fn unicast_style_response_keeps_one_finding_per_source() {
    // Out-of-scope records have no Answers row listing their
    // responders: each source keeps its own finding, whatever the
    // rdata length.
    let mut second = rec("host.local.", 6, "TYPE6", "rdlength=24", 120, false);
    second.source = "192.168.1.9:5353".parse().unwrap();
    let answers = vec![
        rec("host.local.", 6, "TYPE6", "rdlength=22", 120, false),
        second,
    ];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    assert_eq!(
        found
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnicastStyleResponse)
            .count(),
        2,
        "each responder keeps its own finding"
    );
}

#[test]
fn unicast_style_response_flags_soa_not_ns() {
    let answers = vec![
        rec("host.local.", 6, "TYPE6", "rdlength=22", 120, false),
        rec("host.local.", 2, "NS", "host.local.", 120, false),
    ];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    let flagged: Vec<_> = found
        .iter()
        .filter(|a| {
            matches!(
                a.kind,
                AnomalyKind::UnicastStyleResponse | AnomalyKind::UnsupportedType
            )
        })
        .collect();
    // SOA: mDNS zones have none (§12). NS is in scope: no finding.
    assert_eq!(flagged.len(), 1, "{flagged:?}");
    assert_eq!(flagged[0].rtype, Some(6));
    assert_eq!(flagged[0].kind, AnomalyKind::UnicastStyleResponse);
    assert_eq!(flagged[0].severity, Severity::Warning);
}

#[test]
fn unsupported_type_flags_mx_but_not_in_scope_types() {
    let mut ka = rec("host.local.", 15, "TYPE15", "rdlength=9", 120, false);
    ka.section = crate::browse::RecordSection::KnownAnswer;
    let answers = vec![
        rec("host.local.", 15, "TYPE15", "rdlength=9", 120, false),
        rec("host.local.", 99, "TYPE99", "rdlength=4", 120, false),
        rec("host.local.", 5, "CNAME", "alias.local.", 120, false),
        rec("host.local.", 13, "HINFO", "X86_64 LINUX", 120, false),
        rec("host.local.", 47, "NSEC", "host.local. A", 120, false),
    ];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    let unsupported: Vec<_> = found
        .iter()
        .filter(|a| a.kind == AnomalyKind::UnsupportedType)
        .collect();
    let mut types: Vec<_> = unsupported.iter().filter_map(|a| a.rtype).collect();
    types.sort_unstable();
    assert_eq!(types, vec![15, 99], "{unsupported:?}");
    assert!(unsupported.iter().all(|a| a.severity == Severity::Warning));
    assert!(!found
        .iter()
        .any(|a| a.kind == AnomalyKind::UnicastStyleResponse));
    // Known answers ride in queries: capped at Info.
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &[ka]);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::UnsupportedType)
        .expect("expected known-answer finding");
    assert_eq!(item.severity, Severity::Info);
}

#[test]
fn unicast_style_response_names_section_and_unicast_reply() {
    use crate::browse::{QueryTrigger, RecordSection};
    // The message names the section and a unicast destination; the
    // finding carries section and trigger for dumps.
    for (mcast, section, want) in [
        (
            true,
            RecordSection::Authority,
            "unicast DNS-style answer over mDNS: SOA in Authority section \
                 (mDNS uses NSEC for negative answers)",
        ),
        (
            false,
            RecordSection::Answer,
            "unicast DNS-style answer over mDNS: SOA in Answer section \
                 (mDNS zones have no SOA); unicast reply",
        ),
        (
            true,
            RecordSection::Additional,
            "unicast DNS-style answer over mDNS: SOA in Additional section \
                 (mDNS zones have no SOA)",
        ),
    ] {
        let mut soa = rec_with(
            "host.local.",
            6,
            "SOA",
            "host.local. admin 1 2 3 4 5",
            120,
            false,
            mcast,
            section,
        );
        soa.trigger = Some(QueryTrigger {
            question: "host.local. A".to_string(),
            own: true,
        });
        let found = analyze_service("My", "_http._tcp.local", "host.local.", &[soa]);
        let item = found
            .iter()
            .find(|a| a.kind == AnomalyKind::UnicastStyleResponse)
            .expect("expected unicast-style response");
        assert_eq!(item.severity, Severity::Warning, "{section:?}");
        assert_eq!(item.message, want);
        let ctx = item.response.as_ref().expect("response context");
        assert_eq!(ctx.section, section);
        assert_eq!(
            ctx.trigger.as_ref().map(|t| (t.question.as_str(), t.own)),
            Some(("host.local. A", true))
        );
    }
}

#[test]
fn mx_answer_is_quiet() {
    // Neither RFC 6762 nor RFC 6763 restricts MX in mDNS.
    let answers = vec![rec("host.local.", 15, "MX", "10 host.local.", 120, false)];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    assert!(!found
        .iter()
        .any(|a| a.kind == AnomalyKind::UnicastStyleResponse));
}

#[test]
fn soa_serial_churn_dedups_to_one_finding() {
    let answers = vec![
        rec(
            "host.local.",
            6,
            "SOA",
            "host.local. admin 1794425867 21600 1800 43200 10",
            4500,
            false,
        ),
        rec(
            "host.local.",
            6,
            "SOA",
            "host.local. admin 1794425874 21600 1800 43200 10",
            4500,
            false,
        ),
    ];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    assert_eq!(
        found
            .iter()
            .filter(|a| a.kind == AnomalyKind::UnicastStyleResponse)
            .count(),
        1,
        "serial-only differences must not multiply findings"
    );
}

#[test]
fn unicast_soa_expired_and_goodbye_never_flagged() {
    let old = aged(
        rec(
            "host.local.",
            6,
            "SOA",
            "host.local. admin 1794425867 21600 1800 43200 10",
            120,
            false,
        ),
        500,
    );
    let gone = rec(
        "host.local.",
        6,
        "SOA",
        "host.local. admin 1794425874 21600 1800 43200 10",
        0,
        false,
    );
    let answers = vec![old, gone];
    let found = analyze_service("My", "_http._tcp.local", "host.local.", &answers);
    assert!(
        !found
            .iter()
            .any(|a| a.kind == AnomalyKind::UnicastStyleResponse),
        "expired and goodbye SOA must not be flagged"
    );
}

#[test]
fn multicast_types_and_cname_stay_quiet_for_unicast_style() {
    let answers = vec![
        rec(
            "_http._tcp.local.",
            12,
            "PTR",
            "X._http._tcp.local.",
            4500,
            false,
        ),
        rec(
            "X._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 h.local.",
            120,
            true,
        ),
        rec("X._http._tcp.local.", 16, "TXT", "k=v", 4500, true),
        rec("h.local.", 1, "A", "192.168.1.1", 120, true),
        rec("h.local.", 28, "AAAA", "fe80::1", 120, true),
        rec("alias.local.", 5, "CNAME", "h.local.", 120, false),
    ];
    let found = analyze_service("X", "_http._tcp.local", "h.local.", &answers);
    assert!(
        !found
            .iter()
            .any(|a| a.kind == AnomalyKind::UnicastStyleResponse),
        "valid multicast types and CNAME must not be flagged"
    );
}
