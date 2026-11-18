// --- Out-of-scope types (#239) ---

use super::*;

#[test]
fn out_of_scope_record_on_host_is_finding_not_row() {
    let mut app = test_service_app();
    ingest(
        &mut app,
        &raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 15, "TYPE15", "rdlength=9", 4500),
    );
    let rows = service_rows(&app, "Test");
    assert!(!rows.contains(&6) && !rows.contains(&15), "rows: {rows:?}");
    let soa = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse);
    assert_eq!(soa.len(), 1);
    assert_eq!(soa[0].service, "test.local", "owned by the host");
    assert_eq!(soa[0].rdata.as_deref(), Some("rdlength=22"));
    assert_eq!(
        soa[0].response.as_ref().map(|r| r.section),
        Some(browse::RecordSection::Answer)
    );
    let mx = findings_of(&app, anomalies::AnomalyKind::UnsupportedType);
    assert_eq!(mx.len(), 1);
    assert_eq!(mx[0].service, "test.local");
    assert_eq!(mx[0].severity, anomalies::Severity::Warning);
    // Host-owned warnings count once, on the host, not per service.
    let counts = app.anomaly_counts();
    assert_eq!(counts.get("test.local"), Some(&2));
    assert_eq!(counts.get("Test._http._tcp.local"), None);
    // ...and show in the Answers pane of every service on the host.
    select_instance(&mut app, "Test");
    let pane: Vec<_> = shown(&app).into_iter().map(|(a, _)| a.kind).collect();
    assert!(
        pane.contains(&anomalies::AnomalyKind::UnsupportedType),
        "{pane:?}"
    );
    assert!(
        pane.contains(&anomalies::AnomalyKind::UnicastStyleResponse),
        "{pane:?}"
    );
}

#[test]
fn in_scope_other_types_stay_rows_without_findings() {
    let mut app = test_service_app();
    for (rtype, label, rdata) in [
        (2, "NS", "test.local."),
        (5, "CNAME", "alias.local."),
        (13, "HINFO", "X86_64 LINUX"),
        (47, "NSEC", "test.local. A AAAA"),
    ] {
        ingest(
            &mut app,
            &raw_record("test.local.", rtype, label, rdata, 120),
        );
    }
    let rows = service_rows(&app, "Test");
    for rtype in [2, 5, 13, 47] {
        assert!(rows.contains(&rtype), "type {rtype} row missing: {rows:?}");
    }
    assert!(findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse).is_empty());
    assert!(findings_of(&app, anomalies::AnomalyKind::UnsupportedType).is_empty());
}

#[test]
fn any_record_is_error_without_row() {
    let mut app = test_service_app();
    ingest(
        &mut app,
        &raw_record("test.local.", 255, "ANY", "rdlength=0", 120),
    );
    assert!(!service_rows(&app, "Test").contains(&255));
    let found = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, anomalies::Severity::Error);
}

#[test]
fn sighting_on_shared_host_is_recorded_once_for_the_host() {
    let mut app = test_service_app();
    ingest(
        &mut app,
        &raw_record(
            "_ipp._tcp.local.",
            12,
            "PTR",
            "Other._ipp._tcp.local.",
            4500,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Other._ipp._tcp.local.",
            33,
            "SRV",
            "0 0 631 test.local.",
            120,
        ),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    let owners: Vec<_> = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse)
        .into_iter()
        .map(|a| a.service)
        .collect();
    assert_eq!(owners, vec!["test.local"], "one finding, owned by the host");
    // Both services on the host show it in their Answers pane.
    for instance in ["Test", "Other"] {
        select_instance(&mut app, instance);
        assert!(
            shown(&app)
                .iter()
                .any(|(a, _)| a.kind == anomalies::AnomalyKind::UnicastStyleResponse),
            "{instance} pane lacks the host finding"
        );
    }
    // The overlay summary counts it once.
    let warnings = app
        .anomalies()
        .iter()
        .filter(|a| a.severity == anomalies::Severity::Warning)
        .count();
    assert!(
        summary(&app).contains(&format!("{warnings} warning")),
        "{}",
        summary(&app)
    );
    assert_eq!(
        findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse).len(),
        1
    );
}

#[test]
fn sighting_for_pending_instance_is_attributed() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    assert!(app.services.is_empty(), "instance still pending");
    ingest(
        &mut app,
        &raw_record("Test._http._tcp.local.", 15, "TYPE15", "rdlength=9", 120),
    );
    let found = findings_of(&app, anomalies::AnomalyKind::UnsupportedType);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].service, "Test._http._tcp.local");
}

#[test]
fn unmatched_sighting_is_unattributed_and_dumped() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("fritz.box.", 6, "TYPE6", "rdlength=49", 10),
    );
    let found = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].service, anomalies::UNATTRIBUTED_SERVICE);
    let dump = app.state_dump();
    let row = dump
        .anomalies
        .iter()
        .find(|a| a.kind == "unicast-style-response")
        .expect("dumped");
    assert_eq!(row.service, anomalies::UNATTRIBUTED_SERVICE);
    assert_eq!(row.rtype_str.as_deref(), Some("TYPE6"));
    assert_eq!(row.rdata.as_deref(), Some("rdlength=49"));
    assert_eq!(dump.metrics["sightings_current"], 1);
    // Shown under the `(unattributed)` entry, grouped by name.
    let pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Unattributed))
        .expect("(unattributed) entry");
    app.view_state.selected_display = pos;
    app.clamp_selection();
    assert!(shown(&app)
        .iter()
        .any(|(a, _)| a.kind == anomalies::AnomalyKind::UnicastStyleResponse));
}

#[test]
fn rdata_churn_from_one_source_stays_one_sighting() {
    let mut app = test_service_app();
    for len in [22, 23, 24] {
        ingest(
            &mut app,
            &raw_record("test.local.", 6, "TYPE6", &format!("rdlength={len}"), 4500),
        );
    }
    assert_eq!(app.sightings.len(), 1);
    let found = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse);
    assert_eq!(found.len(), 1);
    assert_eq!(
        found[0].rdata.as_deref(),
        Some("rdlength=24"),
        "newest wins"
    );
}

#[test]
fn sighting_expires_with_ttl_and_goodbye_clears_it() {
    let mut app = test_service_app();
    let mut old = raw_record("test.local.", 15, "TYPE15", "rdlength=9", 1);
    old.received_at = Instant::now() - Duration::from_secs(5);
    ingest(&mut app, &old);
    app.evict_expired();
    assert!(app.sightings.is_empty(), "expired at 100% TTL");
    assert!(findings_of(&app, anomalies::AnomalyKind::UnsupportedType).is_empty());

    ingest(
        &mut app,
        &raw_record("test.local.", 15, "TYPE15", "rdlength=9", 120),
    );
    assert_eq!(
        findings_of(&app, anomalies::AnomalyKind::UnsupportedType).len(),
        1
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 15, "TYPE15", "rdlength=9", 0),
    );
    assert!(findings_of(&app, anomalies::AnomalyKind::UnsupportedType).is_empty());
    // The goodbye never touched the service's real rows.
    let svc = app.services.iter().find(|s| s.instance == "Test").unwrap();
    assert!(svc.is_active);
    assert!(svc.answers.iter().all(|r| r.ttl > 0));
}

#[test]
fn sightings_are_capped_and_drops_counted() {
    let mut app = App::new().unwrap();
    for i in 0..=SIGHTINGS_CAP {
        ingest(
            &mut app,
            &raw_record(&format!("h{i}.example."), 15, "TYPE15", "rdlength=9", 120),
        );
    }
    assert_eq!(app.sightings.len(), SIGHTINGS_CAP);
    assert_eq!(app.metrics.sightings_dropped, 1);
    assert!(
        !app.sightings.iter().any(|s| s.rec.name == "h0.example."),
        "oldest evicted first"
    );
    assert_eq!(app.state_dump().metrics["sightings_dropped"], 1);
}

#[test]
fn out_of_scope_records_never_drive_queries() {
    let mut app = test_service_app();
    ingest(
        &mut app,
        &raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    assert!(!app.requeries.keys().any(|k| k.1 == 6));
    assert!(!app.continuous.keys().any(|k| k.1 == 6));
    assert!(!app.refresh_rows.keys().any(|r| r.1 == 6));
}

#[test]
fn late_service_claims_earlier_unattributed_sighting() {
    // An SOA for the host arrives before the host's SRV: unattributed
    // at first, the host's once a service's SRV names it.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    let services = |app: &App| -> Vec<String> {
        findings_of(app, anomalies::AnomalyKind::UnicastStyleResponse)
            .into_iter()
            .map(|a| a.service)
            .collect()
    };
    assert_eq!(services(&app), vec![anomalies::UNATTRIBUTED_SERVICE]);
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    assert_eq!(services(&app), vec!["test.local"]);
}

#[test]
fn out_of_scope_known_answer_is_sighted_in_its_section() {
    let mut app = test_service_app();
    let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let mut ka = raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500);
    ka.section = browse::RecordSection::KnownAnswer;
    ka.source = querier;
    app.ingest_event(&query_event(
        "test.local.",
        1,
        "A",
        false,
        vec![ka],
        querier,
    ));
    let found = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].service, "test.local");
    assert_eq!(
        found[0].severity,
        anomalies::Severity::Info,
        "known answers cap at Info"
    );
    assert_eq!(
        found[0].response.as_ref().map(|r| r.section),
        Some(browse::RecordSection::KnownAnswer)
    );
    assert!(
        found[0].message.contains("Known-Answer"),
        "{}",
        found[0].message
    );
    assert!(!service_rows(&app, "Test").contains(&6));

    // A known answer with TTL 0 is no goodbye: a responder's own
    // sighting of the same record survives it.
    let mut answer = raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500);
    answer.source = querier;
    ingest(&mut app, &answer);
    let mut ka_zero = raw_record("test.local.", 6, "TYPE6", "rdlength=22", 0);
    ka_zero.section = browse::RecordSection::KnownAnswer;
    ka_zero.source = querier;
    app.ingest_event(&query_event(
        "test.local.",
        1,
        "A",
        false,
        vec![ka_zero],
        querier,
    ));
    assert!(
        findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse)
            .iter()
            .any(|a| a.response.as_ref().map(|r| r.section) == Some(browse::RecordSection::Answer)),
        "response sighting survives a TTL-0 known answer"
    );
}

#[test]
fn nsec_question_is_finding_any_question_is_row() {
    let mut app = test_service_app();
    let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    app.ingest_event(&query_event(
        "test.local.",
        47,
        "NSEC",
        false,
        Vec::new(),
        querier,
    ));
    app.ingest_event(&query_event(
        "test.local.",
        255,
        "ANY",
        false,
        Vec::new(),
        querier,
    ));
    let svc = app.services.iter().find(|s| s.instance == "Test").unwrap();
    let types: Vec<&str> = svc.questions.iter().map(|q| q.1.as_str()).collect();
    assert_eq!(types, vec!["ANY"], "only the ANY question is a row");
    let found = findings_of(&app, anomalies::AnomalyKind::UnsupportedQuestion);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].rtype, Some(47));
    assert_eq!(found[0].service, "test.local");
}

#[test]
fn out_of_scope_record_with_non_utf8_owner_is_flagged() {
    let mut app = test_service_app();
    let mut mx = raw_record("test.local.", 15, "TYPE15", "rdlength=9", 120);
    mx.invalid_utf8 = true;
    ingest(&mut app, &mx);
    let found = findings_of(&app, anomalies::AnomalyKind::NonUtf8);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].rtype, Some(15));
    assert_eq!(found[0].service, "test.local");
}

#[test]
fn host_owned_record_files_on_every_sibling_service() {
    // One host backing two services: its HINFO (and NS/CNAME/NSEC)
    // belongs to both, like its addresses.
    let mut app = test_service_app();
    ingest(
        &mut app,
        &raw_record(
            "_ipp._tcp.local.",
            12,
            "PTR",
            "Other._ipp._tcp.local.",
            4500,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Other._ipp._tcp.local.",
            33,
            "SRV",
            "0 0 631 test.local.",
            120,
        ),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 13, "HINFO", "X86_64 LINUX", 120),
    );
    for instance in ["Test", "Other"] {
        assert!(
            service_rows(&app, instance).contains(&13),
            "{instance} lacks the host's HINFO row"
        );
    }
    // An instance-owned record still files on its own service only.
    ingest(
        &mut app,
        &raw_record("Test._http._tcp.local.", 5, "CNAME", "alias.local.", 120),
    );
    assert!(service_rows(&app, "Test").contains(&5));
    assert!(!service_rows(&app, "Other").contains(&5));
}

#[test]
fn host_owned_record_keeps_withdrawn_sibling_grace() {
    let mut app = test_service_app();
    let past = Instant::now() - Duration::from_secs(60);
    {
        let svc = app
            .services
            .iter_mut()
            .find(|s| s.instance == "Test")
            .unwrap();
        svc.is_active = false;
        svc.last_seen = past;
    }
    ingest(
        &mut app,
        &raw_record("test.local.", 13, "HINFO", "X86_64 LINUX", 120),
    );
    let svc = app.services.iter().find(|s| s.instance == "Test").unwrap();
    assert!(!svc.is_active);
    assert_eq!(
        svc.last_seen, past,
        "HINFO must not extend the grace deadline"
    );
    assert!(svc.answers.iter().any(|r| r.rtype == 13));
}

#[test]
fn known_answer_findings_never_exceed_info() {
    // A known answer carries the querier's belief and its remaining
    // TTL: no TTL verdict at all, and the rest stays info.
    let mut app = test_service_app();
    let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let mut ka = raw_record("test.local.", 15, "TYPE15", "rdlength=9", 5);
    ka.section = browse::RecordSection::KnownAnswer;
    ka.invalid_utf8 = true;
    ka.source = querier;
    app.ingest_event(&query_event(
        "test.local.",
        1,
        "A",
        false,
        vec![ka],
        querier,
    ));
    let found: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.rtype == Some(15))
        .collect();
    let kinds: Vec<_> = found.iter().map(|a| a.kind).collect();
    assert!(
        kinds.contains(&anomalies::AnomalyKind::UnsupportedType),
        "{kinds:?}"
    );
    assert!(
        !kinds.iter().any(|k| k.is_ttl()),
        "remaining TTLs get no TTL verdict: {kinds:?}"
    );
    assert!(
        kinds.contains(&anomalies::AnomalyKind::NonUtf8),
        "{kinds:?}"
    );
    assert!(
        found
            .iter()
            .all(|a| a.severity == anomalies::Severity::Info),
        "{found:?}"
    );
    assert_eq!(app.anomaly_counts().get("Test._http._tcp.local"), None);
}

#[test]
fn sighting_contexts_stay_apart_and_goodbye_clears_all() {
    // One responder sends the same SOA in Authority, then in
    // Additional: two verdicts, neither replaces the other.
    let mut app = App::new().unwrap();
    let mut authority = raw_record("fritz.box.", 6, "TYPE6", "rdlength=49", 120);
    authority.section = browse::RecordSection::Authority;
    ingest(&mut app, &authority);
    let mut additional = raw_record("fritz.box.", 6, "TYPE6", "rdlength=49", 120);
    additional.section = browse::RecordSection::Additional;
    ingest(&mut app, &additional);
    let mut sections: Vec<_> = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse)
        .into_iter()
        .map(|a| (a.response.map(|r| r.section.as_str()), a.severity))
        .collect();
    sections.sort_by_key(|(s, _)| *s);
    assert_eq!(
        sections,
        vec![
            (Some("additional"), anomalies::Severity::Info),
            (Some("authority"), anomalies::Severity::Warning),
        ]
    );
    ingest(
        &mut app,
        &raw_record("fritz.box.", 6, "TYPE6", "rdlength=49", 0),
    );
    assert!(findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse).is_empty());
}

#[test]
fn sighting_on_alternate_srv_target_is_owned_by_that_host() {
    // Two live SRVs for one instance: only one target becomes the
    // hostname, yet both targets own their findings, and the
    // service's pane shows both.
    let mut app = test_service_app();
    let mut alt = raw_record(
        "Test._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 other.local.",
        120,
    );
    alt.flush_bit = true;
    alt.source = remote_source();
    ingest(&mut app, &alt);
    for host in ["test.local.", "other.local."] {
        ingest(&mut app, &raw_record(host, 15, "TYPE15", "rdlength=9", 120));
    }
    let mut owners: Vec<_> = findings_of(&app, anomalies::AnomalyKind::UnsupportedType)
        .into_iter()
        .map(|a| (a.record_name.unwrap(), a.service))
        .collect();
    owners.sort();
    assert_eq!(
        owners,
        vec![
            ("other.local.".to_string(), "other.local".to_string()),
            ("test.local.".to_string(), "test.local".to_string()),
        ]
    );
    select_instance(&mut app, "Test");
    let pane = shown(&app)
        .iter()
        .filter(|(a, _)| a.kind == anomalies::AnomalyKind::UnsupportedType)
        .count();
    assert_eq!(pane, 2, "the service pane shows both hosts' findings");
}

#[test]
fn row_less_target_still_lists_its_findings() {
    // The enumeration row has no Answers or Questions rows, only a
    // sighting: its Answers pane must still show the finding, in the
    // enumeration block.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record(
            "_services._dns-sd._udp.local.",
            6,
            "TYPE6",
            "rdlength=22",
            120,
        ),
    );
    app.evict_expired();
    let enum_pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Enum { .. }))
        .expect("enum row");
    app.view_state.selected_display = enum_pos;
    app.clamp_selection();
    assert!(app.selected_detail_entry().is_none(), "no detail rows");
    let pane = shown(&app);
    assert!(
        pane.iter().any(
            |(a, record)| a.kind == anomalies::AnomalyKind::UnicastStyleResponse
                && record.is_none()
        ),
        "{pane:?}"
    );
}

#[test]
fn host_owned_warning_badges_the_host_header_once() {
    let mut app = test_service_app();
    ingest(
        &mut app,
        &raw_record(
            "_ipp._tcp.local.",
            12,
            "PTR",
            "Other._ipp._tcp.local.",
            4500,
        ),
    );
    let mut other_srv = raw_record(
        "Other._ipp._tcp.local.",
        33,
        "SRV",
        "0 0 631 test.local.",
        120,
    );
    other_srv.flush_bit = true;
    ingest(&mut app, &other_srv);
    ingest(
        &mut app,
        &raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    let buf = render_to_buffer(&app, 140, 30);
    let text = rect_text(&buf, buf.area);
    let warn = App::anomaly_level_icon(anomalies::Severity::Warning);
    let badged: Vec<&str> = text
        .lines()
        .filter(|l| l.contains(&format!("[{warn} 1]")))
        .collect();
    assert_eq!(badged.len(), 1, "one badge, got: {badged:?}");
    assert!(
        badged[0].contains("test (2)"),
        "badge sits on the host header: {badged:?}"
    );
}

#[test]
fn host_sighting_keeps_one_finding_per_source() {
    // A router's SOA heard from several responders (its IPv4 and
    // link-local addresses, a repeater): one finding per source, all
    // owned by the host; serial churn per source stays one finding.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record(
            "_fbox._tcp.local.",
            12,
            "PTR",
            "Fritzel._fbox._tcp.local.",
            4500,
        ),
    );
    let mut srv = raw_record(
        "Fritzel._fbox._tcp.local.",
        33,
        "SRV",
        "0 0 49000 fritz.box.",
        120,
    );
    srv.flush_bit = true;
    ingest(&mut app, &srv);
    let sources = [
        "169.254.1.1:5353",
        "192.168.178.109:5353",
        "[fe80::7eff:4dff:fe15:7f88%2]:5353",
    ];
    for src in sources {
        for len in [30, 31] {
            let mut soa = raw_record("fritz.box.", 6, "TYPE6", &format!("rdlength={len}"), 10);
            soa.source = src.parse().unwrap();
            soa.iface = "enp0s25".to_string();
            ingest(&mut app, &soa);
        }
    }
    let found = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse);
    assert!(found.iter().all(|a| a.service == "fritz.box"), "{found:?}");
    let mut got: Vec<String> = found.into_iter().filter_map(|a| a.source).collect();
    got.sort();
    // Named like the old Answers rows: `@iface`, or the zone as-is.
    let mut want = vec![
        "169.254.1.1:5353@enp0s25".to_string(),
        "192.168.178.109:5353@enp0s25".to_string(),
        "[fe80::7eff:4dff:fe15:7f88%2]:5353".to_string(),
    ];
    want.sort();
    assert_eq!(got, want, "one finding per responder and link");
    // The service's host block shows one row per responder.
    app.evict_expired();
    select_instance(&mut app, "Fritzel");
    let rows = shown(&app)
        .iter()
        .filter(|(a, _)| a.kind == anomalies::AnomalyKind::UnicastStyleResponse)
        .count();
    assert_eq!(rows, sources.len());
}

#[test]
fn same_source_on_two_links_keeps_a_sighting_per_link() {
    // One IPv4 address heard on two links: two responders. A goodbye
    // on one link leaves the other link's finding in place.
    let mut app = App::new().unwrap();
    let on = |ifindex: u32, iface: &str, ttl: u32| {
        let mut soa = raw_record("fritz.box.", 6, "TYPE6", "rdlength=30", ttl);
        soa.source = "169.254.1.1:5353".parse().unwrap();
        soa.ifindex = ifindex;
        soa.iface = iface.to_string();
        soa
    };
    ingest(&mut app, &on(2, "enp0s25", 120));
    ingest(&mut app, &on(3, "wlan0", 120));
    let mut sources: Vec<String> = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse)
        .into_iter()
        .filter_map(|a| a.source)
        .collect();
    sources.sort();
    assert_eq!(
        sources,
        vec!["169.254.1.1:5353@enp0s25", "169.254.1.1:5353@wlan0"]
    );
    ingest(&mut app, &on(3, "wlan0", 0));
    let sources: Vec<String> = findings_of(&app, anomalies::AnomalyKind::UnicastStyleResponse)
        .into_iter()
        .filter_map(|a| a.source)
        .collect();
    assert_eq!(sources, vec!["169.254.1.1:5353@enp0s25"]);
}

#[test]
fn expired_srv_no_longer_makes_its_target_an_owned_host() {
    // The selected SRV expires while PTR and sighting stay live: the
    // stale hostname owns nothing, so the sighting is unattributed
    // and the service pane no longer lists it.
    let mut app = test_service_app();
    for r in app.services.iter_mut().flat_map(|s| s.answers.iter_mut()) {
        if r.rtype == 33 {
            r.received_at = Instant::now() - Duration::from_secs(300);
        }
    }
    ingest(
        &mut app,
        &raw_record("test.local.", 15, "TYPE15", "rdlength=9", 4500),
    );
    let owners: Vec<_> = findings_of(&app, anomalies::AnomalyKind::UnsupportedType)
        .into_iter()
        .map(|a| a.service)
        .collect();
    assert_eq!(owners, vec![anomalies::UNATTRIBUTED_SERVICE]);
    select_instance(&mut app, "Test");
    assert!(!shown(&app)
        .iter()
        .any(|(a, _)| a.kind == anomalies::AnomalyKind::UnsupportedType));
}

#[test]
fn same_querier_on_two_links_keeps_a_question_finding_per_link() {
    // One querier address asking an out-of-scope question on two
    // links: two findings, named with their links.
    let mut app = App::new().unwrap();
    let querier: SocketAddr = "169.254.1.1:5353".parse().unwrap();
    for (ifindex, iface) in [(2, "enp0s25"), (3, "wlan0")] {
        let mut ev = query_event("fritz.box.", 6, "TYPE6", false, Vec::new(), querier);
        ev.questions[0].ifindex = ifindex;
        ev.questions[0].iface = iface.to_string();
        app.ingest_event(&ev);
    }
    let mut sources: Vec<String> = findings_of(&app, anomalies::AnomalyKind::UnsupportedQuestion)
        .into_iter()
        .filter_map(|a| a.source)
        .collect();
    sources.sort();
    assert_eq!(
        sources,
        vec!["169.254.1.1:5353@enp0s25", "169.254.1.1:5353@wlan0"]
    );
}

fn service_rows(app: &App, instance: &str) -> Vec<u16> {
    app.services
        .iter()
        .find(|s| s.instance == instance)
        .expect("service")
        .answers
        .iter()
        .map(|r| r.rtype)
        .collect()
}
