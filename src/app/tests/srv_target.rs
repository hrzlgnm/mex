use super::*;

#[test]
fn finding_row_omits_self_referential_rdata() {
    // PTR rdata usually names its own service (here each PTR seeds
    // its own service identity); repeating it after the scope adds no
    // identity beyond the service column, so it stays short — while
    // the two services still tell apart.
    let mut app = App::new().unwrap();
    let mut first = ptr_record(4500);
    first.flush_bit = true;
    ingest(&mut app, &first);
    let mut second = raw_record(
        "_http._tcp.local.",
        12,
        "PTR",
        "Other._http._tcp.local.",
        4500,
    );
    second.flush_bit = true;
    ingest(&mut app, &second);
    ingest(&mut app, &srv_record(120));
    app.evict_expired();
    select_instance(&mut app, "Test");
    let lines = answers_text(&app);
    let row = lines
        .iter()
        .find(|l| l.contains("shared-flush"))
        .unwrap_or_else(|| panic!("finding row: {lines:#?}"));
    assert!(!row.contains(" = "), "self rdata stays short, got: {row}");
}

#[test]
fn enum_question_finding_keeps_qry_scope() {
    // Questions on the enumeration row keep their QRY scope: the
    // queried type varies, so suppressing it would collapse SOA and
    // MX askers into identical rows.
    let mut app = App::new().unwrap();
    let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
    app.ingest_event(&query_event(
        "_services._dns-sd._udp.local.",
        6,
        "TYPE6",
        false,
        Vec::new(),
        stub,
    ));
    let pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Enum { .. }))
        .expect("enum row");
    app.selected_display = pos;
    app.clamp_selection();
    let lines = answers_text(&app);
    assert!(
        lines
            .iter()
            .any(|l| l.contains("QRY TYPE6 _services._dns-sd")),
        "enum question keeps its QRY scope, got: {lines:#?}"
    );
}

#[test]
fn out_of_scope_enumeration_question_is_attributed_to_enumeration() {
    let mut app = App::new().unwrap();
    let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
    app.ingest_event(&query_event(
        "_services._dns-sd._udp.local.",
        6,
        "TYPE6",
        false,
        Vec::new(),
        stub,
    ));
    app.evict_expired();
    assert!(
        app.enum_entries.iter().all(|e| e.questions.is_empty()),
        "no Questions row for an out-of-scope type"
    );
    let item = app
        .anomalies()
        .into_iter()
        .find(|a| a.kind == anomalies::AnomalyKind::UnsupportedQuestion)
        .expect("finding for the SOA question");
    assert_eq!(item.service, anomalies::ENUMERATION_SERVICE);
    assert_eq!(item.severity, anomalies::Severity::Info);
    assert_eq!(item.rtype_str.as_deref(), Some("TYPE6"));
}

#[test]
fn pending_ptr_flush_is_analyzed() {
    // PTR with flush bit but no SRV yet: the row lives in pending, and
    // the analyzer must still see it.
    let mut app = App::new().unwrap();
    let mut bad = ptr_record(120);
    bad.flush_bit = true;
    ingest(&mut app, &bad);
    assert!(app.services.is_empty());
    assert!(!app.pending_instances.is_empty());
    assert!(app
        .anomalies()
        .iter()
        .any(|a| a.kind == anomalies::AnomalyKind::SharedFlush));
}

#[test]
fn out_of_scope_questions_are_findings_not_rows() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    let src_a = remote_source();
    let src_b: SocketAddr = "192.168.1.100:5353".parse().unwrap();
    // Two queriers ask multicast for SOA: RFC 6762 §3 makes that
    // compliant, but SOA is outside mDNS scope: one info finding per
    // querier, and no Questions row.
    for src in [src_a, src_b] {
        app.ingest_event(&query_event(
            "test.local.",
            6,
            "TYPE6",
            false,
            Vec::new(),
            src,
        ));
    }
    // NS and HINFO are in scope: plain rows, no finding.
    app.ingest_event(&query_event(
        "test.local.",
        2,
        "NS",
        false,
        Vec::new(),
        src_a,
    ));
    app.ingest_event(&query_event(
        "test.local.",
        13,
        "HINFO",
        false,
        Vec::new(),
        src_b,
    ));
    app.evict_expired();
    select_instance(&mut app, "Test");
    let found: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.kind == anomalies::AnomalyKind::UnsupportedQuestion)
        .collect();
    assert_eq!(found.len(), 2, "one info finding per querier: {found:?}");
    assert!(found.iter().all(|a| a.rtype == Some(6)
        && a.service == "test.local"
        && a.severity == anomalies::Severity::Info));
    let detail = app.display_detail().expect("service displayed");
    let mut rows: Vec<(String, SocketAddr)> = detail
        .ordered_questions()
        .iter()
        .map(|q| (q.1.clone(), q.2))
        .collect();
    rows.sort();
    let mut want = vec![("HINFO".to_string(), src_b), ("NS".to_string(), src_a)];
    want.sort();
    assert_eq!(rows, want, "only in-scope questions become rows");
}

#[test]
fn omitted_additional_addresses_do_not_report_an_anomaly() {
    let mut app = App::new().unwrap();
    let ptr = ptr_record(4500);
    let mut srv = srv_record(120);
    srv.section = browse::RecordSection::Additional;
    let mut event = event_for(&ptr);
    event.answers = vec![ptr, srv];
    ingest_packet(&mut app, event);

    assert!(app.anomalies().is_empty());

    // Resolving the target through a later query is normal, too.
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    ingest_packet(
        &mut app,
        event_for(&raw_record("test.local.", 1, "A", "192.168.1.10", 120)),
    );
    assert!(app.anomalies().is_empty());
}

#[test]
fn unanswered_address_queries_are_inconclusive() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));

    let findings = app.anomalies();
    let finding = findings
        .iter()
        .find(|a| a.kind.as_str() == "unresolved-srv-target")
        .unwrap_or_else(|| panic!("expected an address-query outcome: {findings:?}"));
    assert_eq!(finding.severity, anomalies::Severity::Info);
    assert!(finding.message.contains("A: no response"));
    assert!(finding.message.contains("AAAA: no response"));
    assert!(finding.message.contains("inconclusive"));
    assert!(!finding.message.contains("NODATA"));
    assert!(!finding.message.contains("NXDOMAIN"));
}

#[test]
fn empty_mdns_response_is_inconclusive_not_a_timeout_or_nodata() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    ingest_packet(
        &mut app,
        browse::Event {
            answers: Vec::new(),
            questions: Vec::new(),
            query_kas: Vec::new(),
            rcode: Some(0),
            received_at: Instant::now(),
            raw_bytes: Vec::new(),
            source: test_source(),
        },
    );

    let finding = app
        .anomalies()
        .into_iter()
        .find(|a| a.kind.as_str() == "unresolved-srv-target")
        .expect("expected an inconclusive address-query outcome");
    assert_eq!(finding.severity, anomalies::Severity::Info);
    assert!(finding.message.contains("unattributed mDNS response"));
    assert!(!finding.message.contains("no response"));
    assert!(!finding.message.contains("NODATA"));
}

#[test]
fn address_queries_remain_pending_during_the_response_window() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::ZERO);

    assert!(!app
        .anomalies()
        .iter()
        .any(|a| a.kind.as_str() == "unresolved-srv-target"));
}

#[test]
fn explicit_nsec_negative_answers_are_distinguished_from_silence() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    let mut nsec = raw_record("test.local.", 47, "NSEC", "test.local. PTR SRV", 120);
    nsec.iface = "br0".to_string();
    ingest_packet(
        &mut app,
        browse::Event {
            answers: vec![nsec],
            questions: Vec::new(),
            query_kas: Vec::new(),
            rcode: Some(0),
            received_at: Instant::now(),
            raw_bytes: Vec::new(),
            source: test_source(),
        },
    );
    let finding = app
        .anomalies()
        .into_iter()
        .find(|a| a.kind.as_str() == "unresolved-srv-target")
        .expect("expected an address-query outcome");
    assert_eq!(
        finding.severity,
        anomalies::Severity::Warning,
        "{finding:?}"
    );
    assert!(finding.message.contains("A: NODATA"));
    assert!(finding.message.contains("AAAA: NODATA"));
    assert!(finding.message.contains("br0"));
    assert!(!finding.message.contains("inconclusive"));
}

#[test]
fn one_nodata_family_does_not_prove_the_srv_target_unresolvable() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    let nsec = raw_record("test.local.", 47, "NSEC", "test.local. AAAA PTR SRV", 120);
    ingest_packet(
        &mut app,
        browse::Event {
            answers: vec![nsec],
            questions: Vec::new(),
            query_kas: Vec::new(),
            rcode: Some(0),
            received_at: Instant::now(),
            raw_bytes: Vec::new(),
            source: test_source(),
        },
    );

    let finding = app
        .anomalies()
        .into_iter()
        .find(|a| a.kind.as_str() == "unresolved-srv-target")
        .expect("expected an address-query outcome");
    assert_eq!(finding.severity, anomalies::Severity::Info);
    assert!(finding.message.contains("A: NODATA"));
    assert!(finding.message.contains("AAAA: unattributed mDNS response"));
    assert!(finding.message.contains("inconclusive"));
}

#[test]
fn one_observed_address_family_resolves_the_srv_target() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    ingest(
        &mut app,
        &raw_record("test.local.", 28, "AAAA", "fe80::1", 120),
    );

    assert!(!app
        .anomalies()
        .iter()
        .any(|a| a.kind.as_str() == "unresolved-srv-target"));
}

#[test]
fn expired_selected_target_does_not_report_against_a_live_alternate() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    let mut alternate = srv_record(120);
    alternate.rdata = "0 0 80 backup.local.".to_string();
    ingest(&mut app, &alternate);

    let expired_at = Instant::now() - Duration::from_secs(2);
    for rec in &mut app.services[0].answers {
        if rec.rtype == 33 && rec.rdata.ends_with("backup.local.") {
            rec.ttl = 1;
            rec.received_at = expired_at;
        }
    }
    mark_address_queries(&mut app, "backup.local", Duration::from_secs(2));

    assert!(!app
        .anomalies()
        .iter()
        .any(|a| a.kind.as_str() == "unresolved-srv-target"));
}

#[test]
fn unicast_style_response_names_its_triggering_question() {
    // The Fritzbox answers a `fritz.box` address query over mDNS with
    // SOA. The finding names that question and whether we asked it.
    fn fritz_app() -> App {
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
        ingest(
            &mut app,
            &raw_record(
                "Fritzel._fbox._tcp.local.",
                33,
                "SRV",
                "0 0 49000 fritz.box.",
                120,
            ),
        );
        app
    }
    fn soa_trigger(app: &mut App) -> Option<browse::QueryTrigger> {
        ingest(
            app,
            &raw_record("fritz.box.", 6, "TYPE6", "rdlength=49", 10),
        );
        let found = app.anomalies();
        let item = found
            .iter()
            .find(|a| a.kind == anomalies::AnomalyKind::UnicastStyleResponse)
            .expect("expected unicast-style response");
        item.response.as_ref().and_then(|r| r.trigger.clone())
    }

    // Our own address query, just sent.
    let mut app = fritz_app();
    mark_address_queries(&mut app, "fritz.box", Duration::from_millis(200));
    let trigger = soa_trigger(&mut app).expect("own query attributed");
    assert!(trigger.own);
    assert!(
        trigger.question.starts_with("fritz.box. "),
        "{}",
        trigger.question
    );
    let dump = app.state_dump();
    let row = dump
        .anomalies
        .iter()
        .find(|a| a.kind == "unicast-style-response")
        .expect("dumped");
    assert_eq!(row.section.as_deref(), Some("answer"));
    assert_eq!(row.in_response_to_own, Some(true));

    // A remote querier's question.
    let mut app = fritz_app();
    let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    app.ingest_event(&query_event(
        "fritz.box.",
        1,
        "A",
        false,
        Vec::new(),
        querier,
    ));
    let trigger = soa_trigger(&mut app).expect("remote query attributed");
    assert!(!trigger.own);
    assert_eq!(trigger.question, "fritz.box. A");

    // A question long before the response is not its trigger.
    let mut app = fritz_app();
    mark_address_queries(&mut app, "fritz.box", Duration::from_secs(5));
    assert_eq!(soa_trigger(&mut app), None);
}

#[test]
fn shared_target_question_is_listed_once_in_global_views() {
    // One `fritz.box SOA` question for the host both services point
    // at: one finding, owned by the host, listed once everywhere.
    let mut app = App::new().unwrap();
    for svc in ["_fbox._tcp.local.", "_tr064._tcp.local."] {
        let instance = format!("Fritzel.{svc}");
        ingest(&mut app, &raw_record(svc, 12, "PTR", &instance, 4500));
        ingest(
            &mut app,
            &raw_record(&instance, 33, "SRV", "0 0 49000 fritz.box.", 120),
        );
    }
    let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    app.ingest_event(&query_event(
        "fritz.box.",
        6,
        "TYPE6",
        false,
        Vec::new(),
        querier,
    ));

    let owners: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.kind == anomalies::AnomalyKind::UnsupportedQuestion)
        .map(|a| a.service)
        .collect();
    assert_eq!(owners, vec!["fritz.box"], "one finding, owned by the host");

    let dump = app.state_dump();
    let dumped: Vec<_> = dump
        .anomalies
        .iter()
        .filter(|a| a.kind == "unsupported-question")
        .collect();
    assert_eq!(dumped.len(), 1, "dump lists the question once");
    assert!(dumped[0].also_services.is_empty());
    assert_eq!(dump.metrics["anomalies_total"], dump.anomalies.len() as u64);

    // The overlay summary counts it once, like the dump: its total
    // equals the deduplicated dump list, not the per-service filings.
    let total: usize = summary(&app)
        .split(" · ")
        .filter_map(|part| part.split(' ').next()?.parse::<usize>().ok())
        .sum();
    assert_eq!(total, dump.anomalies.len(), "{}", summary(&app));
}

#[test]
fn global_srv_target_question_is_not_flagged() {
    // A querier resolving a service's global SRV target over mDNS is
    // doing ordinary DNS-SD (mex and avahi both do): the question is
    // filed on the service, but raises no finding.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record(
            "_avmnexus._tcp.local.",
            12,
            "PTR",
            "Fritzel._avmnexus._tcp.local.",
            4500,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Fritzel._avmnexus._tcp.local.",
            33,
            "SRV",
            "0 0 80 fritz.box.",
            120,
        ),
    );
    let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    app.ingest_event(&query_event(
        "fritz.box.",
        1,
        "A",
        false,
        Vec::new(),
        querier,
    ));
    let svc = app
        .services
        .iter()
        .find(|s| s.instance == "Fritzel")
        .expect("service");
    assert!(
        svc.questions.iter().any(|(name, ..)| name == "fritz.box."),
        "question filed on the service"
    );
    let questions: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.kind.is_question())
        .collect();
    assert!(questions.is_empty(), "got: {questions:?}");
}

#[test]
fn non_local_srv_target_is_scoped_to_mdns_observation() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record(
            "_avmnexus._tcp.local.",
            12,
            "PTR",
            "Fritzel._avmnexus._tcp.local.",
            4500,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Fritzel._avmnexus._tcp.local.",
            33,
            "SRV",
            "0 0 80 fritz.box.",
            120,
        ),
    );
    mark_address_queries(&mut app, "fritz.box", Duration::from_secs(2));

    let finding = app
        .anomalies()
        .into_iter()
        .find(|a| {
            a.kind.as_str() == "unresolved-srv-target"
                && a.service == "Fritzel._avmnexus._tcp.local"
        })
        .expect("expected mDNS address-query outcome");
    assert_eq!(finding.severity, anomalies::Severity::Info);
    assert!(finding.message.contains("fritz.box"));
    assert!(finding.message.contains("unicast DNS may still resolve"));
}

#[test]
fn nonzero_rcode_responses_are_ignored_for_srv_target() {
    // RFC 6762 §18.11: responses with a non-zero RCODE MUST be
    // silently ignored, so an RCODE 3 reply (bare, or carrying a CNAME
    // for the target in any section) is no evidence: the lookup
    // stays an inconclusive "no response".
    let mut cname_answer = raw_record("test.local.", 5, "CNAME", "missing.local.", 120);
    cname_answer.section = browse::RecordSection::Answer;
    let mut cname_additional = cname_answer.clone();
    cname_additional.section = browse::RecordSection::Additional;
    for answers in [Vec::new(), vec![cname_answer], vec![cname_additional]] {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        ingest_packet(
            &mut app,
            browse::Event {
                answers,
                questions: Vec::new(),
                query_kas: Vec::new(),
                rcode: Some(3),
                received_at: Instant::now(),
                raw_bytes: Vec::new(),
                source: test_source(),
            },
        );

        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind.as_str() == "unresolved-srv-target")
            .expect("expected an inconclusive address-query outcome");
        assert_eq!(finding.severity, anomalies::Severity::Info);
        assert!(finding.message.contains("A: no response"));
        assert!(finding.message.contains("AAAA: no response"));
        assert!(finding.message.contains("inconclusive"));
        assert!(!finding.message.contains("NXDOMAIN"));
    }
}

#[test]
fn expired_address_preserves_response_evidence_without_resolving_target() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(10));
    let mut addr = raw_record("test.local.", 1, "A", "192.168.1.10", 1);
    addr.received_at = Instant::now() - Duration::from_secs(5);
    ingest(&mut app, &addr);
    let found = app.anomalies();
    let finding = found
        .iter()
        .find(|a| a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget)
        .unwrap();
    assert!(finding.message.contains("answered; address expired"));
    assert_eq!(finding.severity, anomalies::Severity::Info);
}

#[test]
fn negative_families_on_different_interfaces_do_not_combine() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    for state in app.query_history.values_mut() {
        state.transmitted_interfaces = "br0, eth0".into();
    }
    for (iface, bitmap) in [("br0", "AAAA"), ("eth0", "A")] {
        let mut nsec = raw_record(
            "test.local.",
            47,
            "NSEC",
            &format!("test.local. {bitmap}"),
            120,
        );
        nsec.iface = iface.into();
        ingest_packet(&mut app, event_for(&nsec));
    }
    let found: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget)
        .collect();
    assert_eq!(found.len(), 2);
    assert!(found
        .iter()
        .all(|a| a.severity == anomalies::Severity::Info));
    assert!(found.iter().any(|a| a.message.contains("interfaces br0")));
    assert!(found.iter().any(|a| a.message.contains("interfaces eth0")));
}

#[test]
fn unrelated_response_does_not_turn_silence_into_inconclusive_response() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    ingest_packet(
        &mut app,
        event_for(&raw_record("other.local.", 1, "A", "192.168.1.10", 120)),
    );
    let finding = app
        .anomalies()
        .into_iter()
        .find(|a| a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget)
        .unwrap();
    assert!(finding.message.contains("A: no response"));
    assert!(finding.message.contains("AAAA: no response"));
}

#[test]
fn queried_srv_target_is_analyzed_when_another_host_is_displayed() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    app.services[0].hostname = "display.local".into();
    assert!(app
        .anomalies()
        .iter()
        .any(|a| a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget
            && a.message.contains("test.local")));
}
