use super::*;

#[test]
fn own_questions_filed_on_type_full_and_host() {
    let mut app = two_group_app();
    // Type-level: only the _http service matches.
    app.route_own_question("_http._tcp.local.", 12, false);
    assert_eq!(app.services[0].questions.len(), 1);
    assert!(app.services[1].questions.is_empty());
    let q = &app.services[0].questions[0];
    assert_eq!(q.0, "_http._tcp.local.");
    assert_eq!(q.1, "PTR");
    assert_eq!(q.2, SELF_SOURCE);
    assert!(browse::question_fields(&q.4, &q.0, &q.1).is_some());
    // Full instance name and host name file further rows.
    app.route_own_question("Test._http._tcp.local.", 33, false);
    app.route_own_question("test.local.", 1, false);
    assert_eq!(app.services[0].questions.len(), 3);
    // Re-sending refreshes instead of duplicating.
    app.route_own_question("_http._tcp.local.", 12, false);
    assert_eq!(app.services[0].questions.len(), 3);
    // Enumeration files on its own row, unknown types file nothing.
    app.route_own_question("_services._dns-sd._udp.local.", 12, false);
    app.route_own_question("_http._tcp.local.", 99, false);
    assert_eq!(app.services[0].questions.len(), 3);
    assert!(app.services[1].questions.is_empty());
    assert_eq!(app.enum_entries.len(), 1);
    assert_eq!(app.enum_entries[0].questions.len(), 1);
}

#[test]
fn own_question_packet_preserves_qu_bit() {
    let mut app = two_group_app();
    app.route_own_question("Shell._ssh._tcp.local.", 12, true);
    let question = app
        .services
        .iter()
        .flat_map(|service| &service.questions)
        .find(|question| question.2 == SELF_SOURCE)
        .expect("self question was filed");
    let fields = browse::question_fields(&question.4, &question.0, &question.1)
        .expect("inferred query packet has question fields");
    let qclass = fields
        .iter()
        .find(|field| field.label == "QCLASS / QU")
        .expect("question has QCLASS / QU field");
    assert_eq!(&question.4[qclass.start..qclass.end], &[0x80, 0x01]);
}

#[test]
fn discovery_self_question_survives_promotion() {
    let mut app = App::new().unwrap();
    // PTR first: the instance lives in pending, no service yet.
    ingest(&mut app, &ptr_record(120));
    assert!(app.services.is_empty());
    assert_eq!(app.pending_instances.len(), 1);
    // Our continuous stream asks for the pending SRV: parked, not dropped.
    app.route_own_question("Test._http._tcp.local.", 33, false);
    assert!(app.services.is_empty());
    assert_eq!(app.pending_instances[0].questions.len(), 1);
    // The SRV reply promotes the service with the question kept.
    ingest(&mut app, &srv_record(120));
    assert!(app.pending_instances.is_empty());
    let filed: Vec<_> = app.services[0]
        .questions
        .iter()
        .filter(|q| q.2 == SELF_SOURCE)
        .collect();
    assert_eq!(filed.len(), 1);
    assert_eq!(filed[0].1, "SRV");
}

#[test]
fn active_sends_file_self_questions() {
    let mut app = due_query_setup();
    assert!(app.services[0].questions.is_empty());
    app.send_queries();
    assert_eq!(app.metrics.q_sent_refresh, 1);
    // Dampened interests with cached unique answers file pending
    // rows too; the refresh send itself files exactly one PTR row.
    let filed: Vec<_> = app.services[0]
        .questions
        .iter()
        .filter(|q| q.2 == SELF_SOURCE && q.1 == "PTR")
        .collect();
    assert_eq!(filed.len(), 1);
}

#[test]
fn unsupported_question_routes_as_info_with_display_key() {
    // End-to-end through the real routing path: an observed SOA
    // question for a service's host lands on that host as an
    // info-level unsupported-question finding (RFC 6762 §3 makes
    // asking compliant), badges the host once (info counts, #248),
    // and carries the (name, type, querier) triple.
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let mut q = raw_record("test.local.", 6, "TYPE6", "", 120);
    q.source = querier;
    app.ingest_event(&browse::Event {
        answers: Vec::new(),
        questions: vec![q],
        query_kas: Vec::new(),
        rcode: None,
        received_at: Instant::now(),
        raw_bytes: vec![0x01, 0x02],
        source: querier,
    });
    let item = app
        .anomalies()
        .into_iter()
        .find(|a| a.kind == anomalies::AnomalyKind::UnsupportedQuestion)
        .expect("expected routed SOA unicast question");
    assert_eq!(item.service, "test.local");
    assert_eq!(item.severity, crate::anomalies::Severity::Info);
    assert_eq!(
        app.anomaly_counts().get("test.local").copied(),
        Some(1),
        "info-level host findings badge the host header once"
    );
    assert_eq!(
        (
            item.record_name
                .unwrap()
                .trim_end_matches('.')
                .to_lowercase(),
            item.rtype.unwrap(),
            item.source.unwrap(),
        ),
        ("test.local".to_string(), 6, querier.to_string()),
        "finding must carry the exact display lookup triple"
    );
}

#[test]
fn enum_questions_observed_and_own() {
    let mut app = App::new().unwrap();
    let ev = query_event(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    assert_eq!(app.enum_entries[0].questions.len(), 1);
    assert!(app.services.iter().all(|s| s.questions.is_empty()));
    app.route_own_question("_services._dns-sd._udp.local.", 12, false);
    assert_eq!(app.enum_entries[0].questions.len(), 2);
    assert_eq!(app.enum_entries[0].questions[1].2, SELF_SOURCE);
}

#[test]
fn passive_mode_files_no_self_questions() {
    let setup = due_query_setup();
    let mut app = setup;
    app.passive = true;
    app.send_queries();
    assert!(app.services.iter().all(|s| s.questions.is_empty()));
}

#[test]
fn questions_pane_shows_last_and_due() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    select_instance(&mut app, "Test");
    // Continuous stream exists (browse timer); SRV refresh due now.
    app.poll_continuous();
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 33 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    app.requery_expiring();
    // An observed PTR question from a peer.
    let ev = query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    // An observed-only question for a type we never schedule: no
    // local demand exists, so DUE must stay blank, not "expired".
    let mut soa = raw_record("test.local.", 6, "TYPE6", "", 120);
    soa.source = remote_source();
    app.ingest_event(&browse::Event {
        answers: Vec::new(),
        questions: vec![soa],
        query_kas: Vec::new(),
        rcode: None,
        received_at: Instant::now(),
        raw_bytes: vec![0x01, 0x02],
        source: remote_source(),
    });
    // Backdate the last transmit past the old fixed column width:
    // the full kind word must survive, not clip.
    if let Some(s) = app
        .scheduler
        .query_history_mut()
        .get_mut(&("test._http._tcp.local".to_string(), 33))
    {
        s.transmitted = Some(Instant::now() - Duration::from_secs(4000));
    }
    let text = questions_pane_text(&app);
    assert!(text.contains("LAST"), "header shows LAST:\n{text}");
    assert!(text.contains("DUE"), "header shows DUE:\n{text}");
    assert!(!text.contains("AGE"), "AGE column removed:\n{text}");
    assert!(text.contains("observed"), "observed kind shown:\n{text}");
    assert!(
        text.contains("transmitted"),
        "full kind word shown:\n{text}"
    );
    assert!(text.contains("refresh"), "refresh timer shown:\n{text}");
    // Foreign rows no longer inherit the interest's browse timer;
    // only self rows are schedule-driven, and this scenario has no
    // self PTR row, so "browse" is not rendered here.
    assert!(
        !text.contains("expired"),
        "foreign-only interest has no due:\n{text}"
    );
}

#[test]
fn questions_pane_last_self_suppressed() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    select_instance(&mut app, "Test");
    app.poll_continuous();
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 33 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    app.requery_expiring();
    // Overhear a peer's SRV question so the next refresh is suppressed.
    let ev = query_event(
        "Test._http._tcp.local.",
        33,
        "SRV",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    make_refresh_due(&mut app, "Test._http._tcp.local", 33);
    app.requery_expiring();
    let text = questions_pane_text(&app);
    assert!(
        text.contains("suppressed"),
        "suppressed kind shown:\n{text}"
    );
}

#[test]
fn questions_pane_last_self_no_provenance() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    select_instance(&mut app, "Test");
    // File a self row without recording provenance: LAST must be blank.
    app.route_own_question("_http._tcp.local.", 12, false);
    let text = questions_pane_text(&app);
    assert!(text.contains("—"), "blank LAST shown:\n{text}");
    assert!(text.contains("PTR"), "ptr row shown:\n{text}");
}

#[test]
fn questions_pane_last_foreign_observed() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    select_instance(&mut app, "Test");
    let ev = query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    let text = questions_pane_text(&app);
    assert!(text.contains("observed"), "foreign row observed:\n{text}");
}

#[test]
fn ordered_questions_sort_by_type_then_newest_first() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let svc = &mut app.services[0];
    let old = Instant::now() - Duration::from_secs(30);
    let new = Instant::now();
    let src: std::net::SocketAddr = "192.168.1.9:5353".parse().unwrap();
    svc.questions = vec![
        ("h.local".to_string(), "SRV".to_string(), src, old, vec![]),
        ("h.local".to_string(), "A".to_string(), src, old, vec![]),
        ("h.local".to_string(), "A".to_string(), src, new, vec![]),
    ];
    let ordered = app.services[0].ordered_questions();
    let got: Vec<(&str, bool)> = ordered
        .iter()
        .map(|q| {
            (
                q.1.as_str(),
                q.3.duration_since(old) > Duration::from_secs(1),
            )
        })
        .collect();
    // Type first, then newest first within a type.
    assert_eq!(got, vec![("A", true), ("A", false), ("SRV", false)]);
}

/// Full text of the Questions pane (header + body) for render
/// assertions on columns and cell labels.
fn questions_pane_text(app: &App) -> String {
    let buf = render_to_buffer(app, 120, 40);
    let area = app.layout.questions_rect.get();
    let mut out = String::new();
    for y in area.y..(area.y + area.height) {
        for x in area.x..(area.x + area.width) {
            if let Some(cell) = buf.cell((x, y)) {
                out.push_str(cell.symbol());
            }
        }
        out.push('\n');
    }
    out
}
