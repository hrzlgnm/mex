// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn subtype_keeps_non_utf8_octets_and_escapes_them_in_service_dump() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));

    let label: &'static [u8] = Box::leak(vec![0xff, b'%'].into_boxed_slice());
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
        simple_dns::Name::new_with_labels(labels),
        simple_dns::CLASS::IN,
        4500,
        simple_dns::rdata::RData::PTR(
            simple_dns::Name::new_unchecked("Test._http._tcp.local.").into(),
        ),
    ));
    let bytes = packet.build_bytes_vec().unwrap();
    let event = browse::parse_packet(
        &bytes,
        test_source(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251)),
        "br0",
        3,
    )
    .unwrap();
    app.ingest_event(&event);

    assert_eq!(app.services[0].subtypes, vec![vec![0xff, b'%']]);
    assert_eq!(
        app.dump_service(&app.services[0], &app.address_book())
            .subtypes,
        [r"\xFF%"]
    );
    assert!(!app
        .anomalies()
        .iter()
        .any(|a| a.kind == anomalies::AnomalyKind::TypeFormat));
}

#[test]
fn state_dump_models_mex_state() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "b=2; a=1");
    // known_types (the browse set) is learned on the send tick.
    app.send_queries();
    let dump = app.state_dump();
    assert!(!dump.passive);
    assert_eq!(dump.services.len(), 1);
    let svc = &dump.services[0];
    assert_eq!(svc.instance, "Test");
    assert_eq!(svc.service_type, "_http._tcp.local");
    assert_eq!(svc.hostname, "test.local.");
    assert_eq!(svc.port, 80);
    // TXT pairs sorted by key.
    assert_eq!(svc.txt_records, vec!["a=1".to_string(), "b=2".to_string()]);
    assert!(svc.is_active);
    assert!(!svc.answers.is_empty());
    assert!(dump.service_types.contains(&"_http._tcp.local".to_string()));
    // Top-level keys are mex's own model.
    let v = serde_json::to_value(&dump).unwrap();
    for key in [
        "metadata",
        "passive",
        "services",
        "service_types",
        "metrics",
        "enum_groups",
        "pending",
    ] {
        assert!(v.get(key).is_some(), "missing {key}");
    }
    assert_eq!(v["metadata"]["application_name"], "mex");
    assert_eq!(v["services"][0]["service_type"], "_http._tcp.local");
}

#[test]
fn dump_redacts_high_entropy_txt_values() {
    let mut app = App::new().unwrap();
    service_with_txt(
        &mut app,
        "id=328FEBD442638273B38340E9AFE1E9CB; external_url=https://ha.knulp.home64.de; fn=Schreibtisch",
    );
    app.send_queries();
    let dump = app.state_dump();
    let svc = &dump.services[0];
    assert_eq!(
        svc.txt_records,
        vec![
            "external_url=*REDACTED*".to_string(),
            "fn=Schreibtisch".to_string(),
            "id=*REDACTED*".to_string()
        ]
    );
    let txt = svc
        .answers
        .iter()
        .find(|r| r.rtype_str == "TXT")
        .expect("TXT answer present");
    assert_eq!(
        txt.rdata,
        "id=*REDACTED*; external_url=*REDACTED*; fn=Schreibtisch"
    );
}

#[test]
fn dump_question_row_labels_self_source() {
    let now = Instant::now();
    let own = (
        "_http._tcp.local".to_string(),
        "PTR".to_string(),
        SELF_SOURCE,
        now,
        Vec::new(),
    );
    assert_eq!(
        App::dump_question_row(&own, &AddressBook::new(HashSet::new())).source,
        SELF_SOURCE_LABEL
    );
    let remote = (
        "_http._tcp.local".to_string(),
        "PTR".to_string(),
        "192.168.1.5:5353".parse().unwrap(),
        now,
        Vec::new(),
    );
    assert_eq!(
        App::dump_question_row(&remote, &AddressBook::new(HashSet::new())).source,
        "192.168.1.5:5353"
    );
}

#[test]
fn save_state_dump_to_writes_json_file() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1");
    let dir = std::env::temp_dir().join(format!(
        "mex-dump-test-{}",
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    let json_path = app.save_state_dump_to(&dir).unwrap();
    let json = std::fs::read_to_string(&json_path).unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(parsed["metadata"]["application_name"], "mex");
    assert!(parsed.get("services").is_some());
    std::fs::remove_dir_all(&dir).ok();
}

#[test]
fn dump_redacts_public_ipv6_addresses() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1");
    ingest(
        &mut app,
        &raw_record("test.local.", 28, "AAAA", "2003:e8:bf10:9500::1", 120),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 28, "AAAA", "fd00::1", 120),
    );
    app.send_queries();
    let dump = app.state_dump();
    let svc = &dump.services[0];
    assert!(svc.addresses.contains(&"fd00::1".to_string()));
    assert!(svc.addresses.contains(&"2003:*REDACTED*:1".to_string()));
    assert!(!svc.addresses.iter().any(|a| a.contains("bf10")));
    let aaaa: Vec<_> = svc
        .answers
        .iter()
        .filter(|r| r.rtype_str == "AAAA")
        .collect();
    assert!(!aaaa.is_empty());
    for r in aaaa {
        assert!(!r.rdata.contains("bf10"), "global AAAA leaked: {}", r.rdata);
    }
}

#[test]
fn dump_reports_interest_query_state_and_truncation() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    // Age the SRV into the refresh window and drive one refresh.
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 33 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    app.requery_expiring();
    let dump = app.state_dump();
    let srv = dump
        .interests
        .iter()
        .find(|i| i.rtype == 33)
        .expect("srv interest");
    assert_eq!(srv.timer, "refresh");
    assert_eq!(srv.status, "transmitted");
    assert!(srv.attempt >= 1);
    assert!(srv.next_due_in_secs.is_some());
    assert_eq!(srv.last_origin.as_deref(), Some("transmitted"));
    assert!(srv.last_transmitted_age_secs.is_some());
    assert!(srv.last_suppressed_age_secs.is_none());
    assert!(srv.last_observed_age_secs.is_none());

    // Flood one service question from distinct sources past the
    // safety cap (the earlier self SRV refresh already holds one row,
    // so QUESTION_CAP more pushes evict exactly once).
    for i in 0..QUESTION_CAP {
        let src: std::net::SocketAddr = format!("192.168.{}.{}:5353", 1 + i / 200, 10 + i % 200)
            .parse()
            .unwrap();
        let mut ev = query_event("_http._tcp.local.", 12, "PTR", false, Vec::new(), src);
        ev.questions[0].iface = "br0".to_string();
        app.ingest_event(&ev);
    }
    let dump = app.state_dump();
    let svc = &dump.services[0];
    assert_eq!(svc.questions.len(), QUESTION_CAP);
    assert!(svc.questions_truncated);
    assert_eq!(svc.questions_dropped, 1);
    // The interest records who asked last and on which link.
    let ptr = dump
        .interests
        .iter()
        .find(|i| i.name == "_http._tcp.local" && i.rtype == 12)
        .expect("ptr interest");
    assert_eq!(ptr.last_origin.as_deref(), Some("observed"));
    assert!(ptr.last_observed_age_secs.is_some());
    assert!(ptr.last_transmitted_age_secs.is_none());
    assert_eq!(
        ptr.last_observed_from.as_deref(),
        Some("192.168.1.109:5353")
    );
    assert_eq!(ptr.last_observed_iface.as_deref(), Some("br0"));
}

#[test]
fn dump_lists_answer_only_interests() {
    // Passive mode files answers without any query activity: the
    // authoritative interests section must still list them, with
    // origin absent rather than invented.
    let mut app = App::new_with(true, None).unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let dump = app.state_dump();
    let ptr = dump
        .interests
        .iter()
        .find(|i| i.name == "_http._tcp.local" && i.rtype == 12)
        .expect("ptr interest listed");
    assert_eq!(ptr.status, "answered");
    assert!(ptr.last_origin.is_none());
    let srv = dump
        .interests
        .iter()
        .find(|i| i.name == "test._http._tcp.local" && i.rtype == 33)
        .expect("srv interest listed");
    assert_eq!(srv.status, "answered");
}

#[test]
fn state_dump_reports_pending_address_count() {
    let mut app = App::new_with(true, None).unwrap();
    ingest(
        &mut app,
        &raw_record("lonely.local.", 1, "A", "192.168.1.9", 120),
    );

    assert_eq!(app.state_dump().metrics["pending_addrs"], 1);
}
