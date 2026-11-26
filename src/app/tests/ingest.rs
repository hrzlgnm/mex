// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn record_carries_ingress_interface() {
    let mut app = App::new().unwrap();
    let mut rec = ptr_record(120);
    rec.iface = "br0".to_string();
    ingest(&mut app, &rec);
    ingest(&mut app, &srv_record(120));
    let ptrs = live_ptr_rows(&app);
    assert_eq!(ptrs.len(), 1);
    assert_eq!(ptrs[0].iface, "br0");
}

#[test]
fn goodbye_then_comeback_reactivates() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    assert_eq!(app.services.len(), 1);
    assert!(app.services[0].is_active);

    // Goodbye takes the service offline but keeps it during grace.
    ingest(&mut app, &ptr_record(0));
    assert_eq!(app.services.len(), 1);
    assert!(!app.services[0].is_active);

    // Comeback with valid TTL must show the service as online again.
    ingest(&mut app, &ptr_record(120));
    assert!(app.services[0].is_active);
    let ptrs = live_ptr_rows(&app);
    assert_eq!(ptrs.len(), 1);
    assert_eq!(ptrs[0].ttl, 120);

    // A fresh SRV burst merges pending state without duplicating the
    // PTR row or dropping back offline.
    ingest(&mut app, &srv_record(120));
    assert!(app.services[0].is_active);
    let ptrs = live_ptr_rows(&app);
    assert_eq!(ptrs.len(), 1);
    assert_eq!(ptrs[0].ttl, 120);
}

#[test]
fn txt_after_srv_lands_on_live_service() {
    // Passive-mode order: PTR, SRV (service confirmed), then TXT.
    // The late TXT must not strand in pending.
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    assert!(app.services[0]
        .ordered_answers()
        .iter()
        .all(|r| r.rtype != 16));
    ingest(&mut app, &txt_record("a=1; b=2"));
    assert!(app.services[0]
        .ordered_answers()
        .iter()
        .any(|r| r.rtype == 16));
}

#[test]
fn subtype_after_srv_merges_into_live_service() {
    // Same passive-mode order for DNS-SD subtypes (e.g. Google Cast
    // group IDs under `..._sub._googlecast._tcp.local`).
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    assert!(app.services[0].subtypes.is_empty());
    ingest(
        &mut app,
        &raw_record(
            "_printer._sub._http._tcp.local.",
            12,
            "PTR",
            "Test._http._tcp.local.",
            120,
        ),
    );
    assert_eq!(app.services[0].subtypes, vec![b"_printer".to_vec()]);
    assert!(app.services[0]
        .ordered_answers()
        .iter()
        .any(|r| r.rtype == 12 && r.name == "_printer._sub._http._tcp.local."));
    // No stranded pending entry for the confirmed instance.
    assert!(app.pending_instances.is_empty());
}

#[test]
fn subtype_without_underscore_and_restricted_characters_is_valid() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record(
            "%%0B3BFD96-5017-44DB-96E1-BEC3451F7DE2._sub._googlecast._tcp.local.",
            12,
            "PTR",
            "Google-Home._googlecast._tcp.local.",
            4500,
        ),
    );

    assert_eq!(
        app.pending_instances[0].subtypes,
        vec![b"%%0B3BFD96-5017-44DB-96E1-BEC3451F7DE2".to_vec()]
    );
    assert!(!app
        .anomalies()
        .iter()
        .any(|a| a.kind == anomalies::AnomalyKind::TypeFormat));
}

#[test]
fn service_types_match_case_insensitively() {
    // `_HTTP` and `_http` are one service (RFC 6763 §7); same for the
    // `._sub.` marker and instance matching.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record(
            "_HTTP._TCP.LOCAL.",
            12,
            "PTR",
            "Test._HTTP._TCP.LOCAL.",
            120,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Test._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 test.local.",
            120,
        ),
    );
    assert_eq!(app.services.len(), 1);
    ingest(
        &mut app,
        &raw_record(
            "_PRINTER._SUB._http._tcp.local.",
            12,
            "PTR",
            "Test._http._tcp.local.",
            120,
        ),
    );
    assert_eq!(app.services.len(), 1);
    assert_eq!(app.services[0].subtypes.len(), 1);
    // One continuous interest, not one per case variant.
    let desired = app.desired_continuous();
    let ptr_keys: Vec<_> = desired.keys().filter(|(_, t)| *t == 12).collect();
    assert!(ptr_keys.iter().any(|(n, _)| n == "_http._tcp.local"));
    assert_eq!(
        ptr_keys
            .iter()
            .filter(|(n, _)| n.eq_ignore_ascii_case("_http._tcp.local"))
            .count(),
        1
    );
}

#[test]
fn non_ascii_instance_names_do_not_panic_split() {
    // `é` is two bytes in UTF-8: byte-slicing at `len - known.len()`
    // can land inside the character. Splitting must skip such
    // candidates instead of panicking in `split_at`.
    let mut app = App::new().unwrap();
    app.scheduler
        .known_types_mut()
        .insert("_https._tcp.local".to_string());
    assert!(app.split_instance_type("é._ssh._tcp.local").is_none());
    assert_eq!(
        App::strip_suffix_ci("é._ssh._tcp.local", "_https._tcp.local"),
        None
    );
    // Sanity: ASCII suffix matching still works.
    assert_eq!(
        App::strip_suffix_ci("Test._http._tcp.local", "_HTTP._TCP.LOCAL"),
        Some("Test")
    );
}

#[test]
fn enum_query_kas_never_become_answers() {
    // Sibling-style enumeration query: one question plus known answers
    // (RFC 6762 §7.1). KAs are beliefs, not sightings: in passive mode
    // (or any mode) they must never land in the Answers pane nor in the
    // known-answer bookkeeping. A genuine response still files normally.
    let mut app = App::new().unwrap();
    app.passive = true;
    let kas = [
        "_dacp._tcp.local.",
        "_mass._tcp.local.",
        "_http._tcp.local.",
    ]
    .iter()
    .map(|t| ka_record("_services._dns-sd._udp.local.", t))
    .collect();
    let ev = query_event(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        false,
        kas,
        remote_source(),
    );
    app.ingest_event(&ev);
    assert_eq!(app.enum_entries[0].questions.len(), 1);
    assert!(
        app.enum_entries[0].answers.is_empty(),
        "query KAs must not become enumeration answers"
    );
    assert!(
        app.scheduler.enum_known().is_empty(),
        "query KAs must not seed known-answer bookkeeping"
    );
    assert!(app.scheduler.known_types().is_empty());

    let ans = raw_record(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_dacp._tcp.local.",
        4500,
    );
    let ev = event_for(&ans);
    app.ingest_event(&ev);
    assert_eq!(app.enum_entries[0].answers.len(), 1);
    assert!(app.scheduler.enum_known().contains_key("_dacp._tcp.local"));
    assert!(app.scheduler.known_types().contains("_dacp._tcp.local"));
}

#[test]
fn enum_answers_coalesce_wire_case_variants() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_http._tcp.local.",
            120,
        ),
    );
    // Same answer in different wire case: DNS names compare
    // case-insensitively, so this refreshes the row instead of
    // growing the list.
    ingest(
        &mut app,
        &raw_record(
            "_SERVICES._DNS-SD._UDP.LOCAL.",
            12,
            "PTR",
            "_HTTP._TCP.LOCAL.",
            120,
        ),
    );
    assert_eq!(app.enum_entries[0].answers.len(), 1);
}

#[test]
fn enum_subtype_targets_with_lossy_collisions_remain_distinct() {
    let target = |byte: u8| {
        let subtype: &'static [u8] = Box::leak(vec![byte].into_boxed_slice());
        let labels: &'static [simple_dns::Label<'static>] = Box::leak(
            vec![
                simple_dns::Label::new_unchecked(subtype),
                simple_dns::Label::new_unchecked(&b"_sub"[..]),
                simple_dns::Label::new_unchecked(&b"_http"[..]),
                simple_dns::Label::new_unchecked(&b"_tcp"[..]),
                simple_dns::Label::new_unchecked(&b"local"[..]),
            ]
            .into_boxed_slice(),
        );
        simple_dns::Name::new_with_labels(labels)
    };
    let mut packet = simple_dns::Packet::new_reply(0);
    for byte in [0xfe, 0xff] {
        packet.answers.push(simple_dns::ResourceRecord::new(
            simple_dns::Name::new_unchecked("_services._dns-sd._udp.local."),
            simple_dns::CLASS::IN,
            4500,
            simple_dns::rdata::RData::PTR(target(byte).into()),
        ));
    }
    let bytes = packet.build_bytes_vec().unwrap();
    let event = browse::parse_packet(
        &bytes,
        test_source(),
        std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251)),
        "br0",
        3,
    )
    .unwrap();
    let mut app = App::new().unwrap();
    app.ingest_event(&event);

    assert_eq!(app.enum_entries[0].answers.len(), 2);
    assert_eq!(app.enum_entries[0].ordered_answers().len(), 2);
    let messages: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|anomaly| anomaly.kind == anomalies::AnomalyKind::EnumSubtype)
        .map(|anomaly| anomaly.message)
        .collect();
    assert_eq!(messages.len(), 2);
    assert!(messages.iter().any(|message| message.contains(r"\xFE")));
    assert!(messages.iter().any(|message| message.contains(r"\xFF")));
}

#[test]
fn reverse_ptr_creates_no_pending_service() {
    // Reverse-mapping PTRs map addresses to hostnames; they are not
    // service enumeration and must not seed (phantom) services.
    let mut app = App::new().unwrap();
    let rec = raw_record(
        "Android.local.37.178.168.192.in-addr.arpa.",
        12,
        "PTR",
        "Android.local.",
        120,
    );
    let ev = browse::Event {
        answers: vec![rec],
        questions: vec![],
        query_kas: vec![],
        rcode: Some(0),
        received_at: Instant::now(),
        raw_bytes: vec![],
        source: test_source(),
    };
    app.ingest_event(&ev);
    assert!(app.services.is_empty());
    assert!(app.pending_instances.is_empty());
    assert!(
        app.anomalies()
            .iter()
            .all(|a| a.kind != anomalies::AnomalyKind::TypeFormat),
        "reverse name must not flag"
    );
}

#[test]
fn shared_hostname_a_record_reaches_every_service() {
    let mut app = two_on_shared_host_app();
    ingest(
        &mut app,
        &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
    );
    assert!(has_live_a(&app, "One"), "A missing on One");
    assert!(has_live_a(&app, "Two"), "A missing on Two");
}

#[test]
fn late_joiner_backfills_shared_hostname_a_record() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "Two._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record(
            "One._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 shared.local.",
            120,
        ),
    );
    // Address lands while only One is confirmed: it must still reach
    // Two once its SRV promotes it.
    ingest(
        &mut app,
        &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
    );
    ingest(
        &mut app,
        &raw_record(
            "Two._http._tcp.local.",
            33,
            "SRV",
            "0 0 8080 shared.local.",
            120,
        ),
    );
    assert_eq!(app.services.len(), 2);
    assert!(has_live_a(&app, "One"), "A missing on One");
    assert!(has_live_a(&app, "Two"), "A missing on late joiner Two");
}

#[test]
fn shared_hostname_a_goodbye_reaches_every_service() {
    let mut app = two_on_shared_host_app();
    ingest(
        &mut app,
        &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
    );
    assert!(has_live_a(&app, "One") && has_live_a(&app, "Two"));
    ingest(
        &mut app,
        &raw_record("shared.local.", 1, "A", "192.168.1.10", 0),
    );
    // Both services keep the row as an expired goodbye; neither keeps
    // a live address, and both stay browsable (A never deactivates).
    for instance in ["One", "Two"] {
        let svc = app
            .services
            .iter()
            .find(|s| s.instance == instance)
            .expect("service present");
        assert!(
            svc.answers
                .iter()
                .any(|r| r.rtype == 1 && r.rdata == "192.168.1.10" && r.ttl == 0),
            "goodbye row missing on {instance}"
        );
        assert!(!has_live_a(&app, instance), "live A stranded on {instance}");
        assert!(svc.is_active, "{instance} deactivated by an A goodbye");
    }
}

#[test]
fn pending_address_flush_reaches_every_service() {
    let mut app = App::new().unwrap();
    // Address arrives before either SRV: no hostname matches, so it
    // parks in pending_addrs. The ingest helper never flushes, which
    // is exactly what this exercises.
    ingest(
        &mut app,
        &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
    );
    ingest(
        &mut app,
        &raw_record("shared.local.", 1, "A", "192.168.1.11", 120),
    );
    assert!(app.services.is_empty());
    assert_eq!(app.pending_addrs_count(), 2);
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "Two._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record(
            "One._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 shared.local.",
            120,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Two._http._tcp.local.",
            33,
            "SRV",
            "0 0 8080 shared.local.",
            120,
        ),
    );
    // Backfill finds no sibling rows (nothing flushed yet), so the
    // parked address is still pending until the drain-time flush.
    app.flush_pending_addrs();
    assert!(app.pending_addrs.is_empty());
    for instance in ["One", "Two"] {
        let service = app
            .services
            .iter()
            .find(|service| service.instance == instance)
            .unwrap();
        assert_eq!(
            service.answers.iter().filter(|r| r.rtype == 1).count(),
            2,
            "pending A records missing on {instance}"
        );
    }
}

#[test]
fn unrelated_packet_batch_does_not_flush_pending_addresses() {
    let mut app = App::new_with(true, None).unwrap();
    let (tx, rx) = mpsc::channel();
    app.rx = rx;

    tx.send(event_for(&raw_record(
        "test.local.",
        1,
        "A",
        "192.168.1.10",
        120,
    )))
    .unwrap();
    app.drain_events();
    assert_eq!(app.pending_addrs_count(), 1);

    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));

    tx.send(event_for(&raw_record(
        "unrelated.local.",
        1,
        "A",
        "192.168.1.11",
        120,
    )))
    .unwrap();
    app.drain_events();

    assert!(app.pending_addrs.contains_key("test.local"));

    tx.send(event_for(&srv_record(120))).unwrap();
    app.drain_events();

    assert!(!app.pending_addrs.contains_key("test.local"));
    assert!(has_live_a(&app, "Test"));
}

#[test]
fn pending_address_flush_includes_live_alternate_srv_targets() {
    let mut app = App::new_with(true, None).unwrap();
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "Svc._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record(
            "Svc._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 host-a.local.",
            120,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Svc._http._tcp.local.",
            33,
            "SRV",
            "0 0 8080 host-b.local.",
            120,
        ),
    );
    app.pending_addrs.insert(
        "host-a.local".to_string(),
        vec![raw_record("host-a.local.", 1, "A", "192.168.1.10", 120)],
    );
    app.flush_pending_addrs();

    assert!(app.pending_addrs.is_empty());
    assert_eq!(app.services[0].hostname, "host-b.local.");
    assert!(app.services[0]
        .answers
        .iter()
        .any(|r| r.rtype == 1 && r.rdata == "192.168.1.10"));
}

#[test]
fn backfill_ignores_sibling_rows_from_old_hostname() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "Two._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record("One._http._tcp.local.", 33, "SRV", "0 0 80 old.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record("old.local.", 1, "A", "192.168.0.5", 120),
    );
    // One moves to the shared host; its old-host rows stay put.
    ingest(
        &mut app,
        &raw_record(
            "One._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 shared.local.",
            120,
        ),
    );
    // Promoting Two must not inherit One's old-host address.
    ingest(
        &mut app,
        &raw_record(
            "Two._http._tcp.local.",
            33,
            "SRV",
            "0 0 8080 shared.local.",
            120,
        ),
    );
    let two = app
        .services
        .iter()
        .find(|s| s.instance == "Two")
        .expect("Two present");
    assert!(
        two.answers.iter().all(|r| r.rtype != 1 && r.rtype != 28),
        "old-host address leaked onto Two"
    );
    let one = app
        .services
        .iter()
        .find(|s| s.instance == "One")
        .expect("One present");
    assert!(one
        .answers
        .iter()
        .any(|r| r.rtype == 1 && r.rdata == "192.168.0.5"));
}

#[test]
fn host_name_does_not_flap_on_alternating_srv_targets() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "Svc._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record(
            "Svc._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 host-a.local.",
            120,
        ),
    );
    assert_eq!(app.services[0].hostname, "host-a.local.");
    assert_eq!(app.services[0].port, 80);
    // A genuinely new target moves the service.
    ingest(
        &mut app,
        &raw_record(
            "Svc._http._tcp.local.",
            33,
            "SRV",
            "0 0 8080 host-b.local.",
            120,
        ),
    );
    assert_eq!(app.services[0].hostname, "host-b.local.");
    assert_eq!(app.services[0].port, 8080);
    // Refreshing the now-known alternate target must not flip back or
    // change the selected target's port.
    ingest(
        &mut app,
        &raw_record(
            "Svc._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 host-a.local.",
            120,
        ),
    );
    assert_eq!(app.services[0].hostname, "host-b.local.");
    assert_eq!(app.services[0].port, 8080);
    ingest(
        &mut app,
        &raw_record(
            "Svc._http._tcp.local.",
            33,
            "SRV",
            "0 0 8080 host-b.local.",
            120,
        ),
    );
    assert_eq!(app.services[0].hostname, "host-b.local.");
    assert_eq!(app.services[0].port, 8080);
    // Addresses published only under the alternate target are still
    // filed on the service and surfaced on the selected host.
    ingest(
        &mut app,
        &raw_record("host-a.local.", 1, "A", "192.168.1.10", 120),
    );
    assert!(app.services[0]
        .answers
        .iter()
        .any(|r| r.rtype == 1 && r.rdata == "192.168.1.10"));
    assert!(app
        .host_addresses("host-b.local")
        .contains(&"192.168.1.10".to_string()));
    // A refresh after expiry of the alternate-target address is still
    // routed and displayed.
    ingest(
        &mut app,
        &raw_record("host-a.local.", 1, "A", "192.168.1.10", 0),
    );
    assert!(!app
        .host_addresses("host-b.local")
        .contains(&"192.168.1.10".to_string()));
    ingest(
        &mut app,
        &raw_record("host-a.local.", 1, "A", "192.168.1.10", 120),
    );
    assert!(app
        .host_addresses("host-b.local")
        .contains(&"192.168.1.10".to_string()));
    for rec in &mut app.services[0].answers {
        if rec.rtype == 1 && rec.rdata == "192.168.1.10" {
            rec.received_at = Instant::now() - Duration::from_secs(121);
        }
    }
    assert!(!app
        .host_addresses("host-b.local")
        .contains(&"192.168.1.10".to_string()));
    ingest(
        &mut app,
        &raw_record("host-a.local.", 1, "A", "192.168.1.10", 120),
    );
    assert!(app
        .host_addresses("host-b.local")
        .contains(&"192.168.1.10".to_string()));
}

#[test]
fn stale_alternate_target_does_not_route_addr_goodbye() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "Svc._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record(
            "Svc._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 host-b.local.",
            120,
        ),
    );
    app.services[0].answers.push(raw_record(
        "Svc._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 host-a.local.",
        0,
    ));
    ingest(
        &mut app,
        &raw_record("host-a.local.", 1, "A", "192.168.1.10", 0),
    );
    assert!(!app.services[0]
        .answers
        .iter()
        .any(|r| r.rtype == 1 && r.rdata == "192.168.1.10"));
    assert!(!app
        .host_addresses("host-b.local")
        .contains(&"192.168.1.10".to_string()));
}

#[test]
fn addr_on_withdrawn_service_keeps_grace_deadline() {
    let mut app = two_on_shared_host_app();
    ingest(
        &mut app,
        &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
    );
    // Withdraw One; it lingers inactive through the grace period.
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 0),
    );
    let deadline = app
        .services
        .iter()
        .find(|s| s.instance == "One")
        .expect("One present")
        .last_seen;
    assert!(
        !app.services
            .iter()
            .find(|s| s.instance == "One")
            .expect("One present")
            .is_active
    );
    // A subsequent shared-host announcement still files its row...
    ingest(
        &mut app,
        &raw_record("shared.local.", 1, "A", "192.168.1.11", 120),
    );
    let one = app
        .services
        .iter()
        .find(|s| s.instance == "One")
        .expect("One present");
    assert!(one
        .answers
        .iter()
        .any(|r| r.rtype == 1 && r.rdata == "192.168.1.11"));
    // ...without extending the grace deadline; the sibling is unaffected.
    assert_eq!(one.last_seen, deadline);
    assert!(has_live_a(&app, "Two"));
}

#[test]
fn pending_addrs_count_as_live_answers() {
    let mut app = App::new().unwrap();
    // An A record arrives before any SRV names the host: parked in
    // pending_addrs, still a live answer for the interest.
    let mut rec = raw_record("lonely.local.", 1, "A", "192.168.1.9", 120);
    rec.source = remote_source();
    ingest(&mut app, &rec);
    assert_eq!(app.pending_addrs_count(), 1);
    let view = app.interest_view(&("lonely.local".to_string(), 1));
    assert_eq!(view.status, InterestStatus::Answered);
}

#[test]
fn repeated_unmatched_addresses_do_not_accumulate() {
    let mut app = App::new().unwrap();
    for _ in 0..8 {
        ingest(
            &mut app,
            &raw_record("lonely.local.", 1, "A", "192.168.1.9", 120),
        );
    }
    assert_eq!(app.pending_addrs_count(), 1);
}

#[test]
fn expired_unmatched_addresses_are_evicted() {
    let mut app = App::new().unwrap();
    let mut rec = raw_record("lonely.local.", 1, "A", "192.168.1.9", 1);
    rec.received_at = Instant::now() - Duration::from_secs(2);
    ingest(&mut app, &rec);
    assert_eq!(app.pending_addrs_count(), 1);

    app.next_pending_addr_prune = Instant::now();
    app.evict_expired();

    assert!(app.pending_addrs.is_empty());
}

#[test]
fn nonzero_rcode_response_records_are_not_ingested() {
    // RFC 6762 §18.11: the whole message is ignored, so an address in
    // an RCODE 3 reply neither resolves the SRV target nor files a row.
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
    ingest_packet(
        &mut app,
        browse::Event {
            answers: vec![raw_record("test.local.", 1, "A", "192.168.1.10", 120)],
            questions: Vec::new(),
            query_kas: Vec::new(),
            rcode: Some(3),
            received_at: Instant::now(),
            raw_bytes: vec![0x01],
            source: test_source(),
        },
    );
    assert!(app.services[0].answers.iter().all(|r| r.rtype != 1));
    assert_eq!(app.raw_events.len(), 1, "packet log keeps the raw packet");
    let finding = app
        .anomalies()
        .into_iter()
        .find(|a| a.kind.as_str() == "unresolved-srv-target")
        .expect("target stays unresolved");
    assert!(finding.message.contains("A: no response"));
}

fn live_ptr_rows(app: &App) -> Vec<browse::RawRecord> {
    app.services
        .iter()
        .flat_map(|s| s.ordered_answers())
        .filter(|r| r.rtype == 12)
        .cloned()
        .collect()
}

/// Two instances of one type sharing a single hostname: the shape
/// behind the fan-out bug (many SRVs, one host).
fn two_on_shared_host_app() -> App {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record("_http._tcp.local.", 12, "PTR", "Two._http._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record(
            "One._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 shared.local.",
            120,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Two._http._tcp.local.",
            33,
            "SRV",
            "0 0 8080 shared.local.",
            120,
        ),
    );
    assert_eq!(app.services.len(), 2);
    app
}

fn has_live_a(app: &App, instance: &str) -> bool {
    app.services
        .iter()
        .find(|s| s.instance == instance)
        .expect("service present")
        .answers
        .iter()
        .any(|r| {
            r.rtype == 1
                && r.rdata == "192.168.1.10"
                && r.ttl > r.received_at.elapsed().as_secs() as u32
        })
}

/// Backdate every answer of `rtype` past its TTL.
fn expire_answers(app: &mut App, rtype: u16) {
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == rtype {
                rec.received_at = Instant::now() - Duration::from_secs(u64::from(rec.ttl) + 1);
            }
        }
    }
}

#[test]
fn a_service_whose_ptr_expires_turns_inactive_even_with_a_live_srv() {
    let mut app = test_service_app();
    assert_eq!(
        diagnostics_value(&app, "services"),
        "1 (1 active, 0 inactive)"
    );
    expire_answers(&mut app, 12);
    app.evict_expired();
    assert_eq!(
        diagnostics_value(&app, "services"),
        "1 (0 active, 1 inactive)",
        "withdrawn although the SRV is still answered"
    );
}

#[test]
fn a_service_seen_only_by_its_srv_turns_inactive_when_it_expires() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &srv_record(120));
    assert_eq!(
        diagnostics_value(&app, "services"),
        "1 (1 active, 0 inactive)"
    );
    expire_answers(&mut app, 33);
    app.evict_expired();
    assert_eq!(
        diagnostics_value(&app, "services"),
        "1 (0 active, 1 inactive)"
    );
}

#[test]
fn subtype_without_wire_labels_is_parsed_from_its_name() {
    // Records without raw owner labels fall back to the text name.
    let mut app = test_service_app();
    let mut sub = raw_record(
        "_printer._sub._http._tcp.local.",
        12,
        "PTR",
        "Test._http._tcp.local.",
        120,
    );
    sub.owner_labels.clear();
    ingest(&mut app, &sub);
    assert_eq!(app.services[0].subtypes, vec![b"_printer".to_vec()]);
}

#[test]
fn enumeration_goodbyes_withdraw_the_row_or_file_a_new_one() {
    let mut app = App::new().unwrap();
    let responder = "192.168.1.2:5353";
    ingest(&mut app, &enum_row("_http._tcp.local.", 4500, responder, 0));
    let enum_answers = |app: &App| {
        app.enum_entries
            .iter()
            .flat_map(|e| e.answers.iter())
            .map(|r| (r.rdata.clone(), r.ttl))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        enum_answers(&app),
        vec![("_http._tcp.local.".to_string(), 4500)]
    );

    // A goodbye for the announced type replaces its row...
    ingest(&mut app, &enum_row("_http._tcp.local.", 0, responder, 0));
    assert_eq!(
        enum_answers(&app),
        vec![("_http._tcp.local.".to_string(), 0)]
    );
    // ...and one for a type never announced is still shown.
    ingest(&mut app, &enum_row("_ipp._tcp.local.", 0, responder, 0));
    assert_eq!(
        enum_answers(&app),
        vec![
            ("_http._tcp.local.".to_string(), 0),
            ("_ipp._tcp.local.".to_string(), 0)
        ]
    );
}

#[test]
fn ptr_targets_compare_by_labels_or_rdata_never_mixed() {
    let with_labels = raw_record("_http._tcp.local.", 12, "PTR", "A._http._tcp.local.", 120);
    let mut upper = with_labels.clone();
    upper.ptr_target_labels = Some(vec![
        b"a".to_vec(),
        b"_HTTP".to_vec(),
        b"_tcp".to_vec(),
        b"local".to_vec(),
    ]);
    assert!(same_ptr_target(&with_labels, &upper), "labels ignore case");
    let mut no_labels = with_labels.clone();
    no_labels.ptr_target_labels = None;
    let mut no_labels_upper = no_labels.clone();
    no_labels_upper.rdata = "a._HTTP._tcp.local.".to_string();
    assert!(
        same_ptr_target(&no_labels, &no_labels_upper),
        "rdata ignores case"
    );
    assert!(
        !same_ptr_target(&with_labels, &no_labels),
        "mixed forms differ"
    );
}

#[test]
fn five_label_owner_without_sub_is_no_subtype() {
    let rec = raw_record(
        "printer.ipp._ipp._tcp.local.",
        12,
        "PTR",
        "P._ipp._tcp.local.",
        120,
    );
    assert!(subtype_owner_parts(&rec).is_none());
}

#[test]
fn raw_event_history_keeps_the_newest_2000() {
    let mut app = App::new().unwrap();
    let (tx, rx) = mpsc::channel();
    app.rx = rx;
    for ttl in 0..2001 {
        tx.send(event_for(&ptr_record(ttl))).unwrap();
    }
    app.drain_events();
    assert_eq!(app.raw_events.len(), 2000);
    assert_eq!(app.raw_events[0].answers[0].ttl, 1, "the oldest went");
}

#[test]
fn rate_windows_drop_entries_past_the_window_on_idle_ticks() {
    let Some(old) = Instant::now().checked_sub(DIAGNOSTICS_WINDOW + Duration::from_secs(1)) else {
        return; // host clock too young to backdate past the window
    };
    let mut app = App::new().unwrap();
    // No live traffic: a packet arriving mid-test would add a fresh entry.
    let (_tx, rx) = mpsc::channel();
    app.rx = rx;
    app.diagnostics.packet_times.push_back(old);
    app.diagnostics.suppressed_times.push_back(old);
    app.drain_events();
    assert!(app.diagnostics.packet_times.is_empty());
    assert!(app.diagnostics.suppressed_times.is_empty());
}

#[test]
fn srv_without_target_claims_no_pending_addresses() {
    // RFC 2782: target "." means "no service here". Such an SRV, and a
    // service with no hostname yet, never pick up a host's addresses.
    let mut app = App::new().unwrap();
    let mut lonely = ServiceEntry {
        instance: "Lonely".to_string(),
        service_type: "_http._tcp.local".to_string(),
        hostname: String::new(),
        port: 0,
        subtypes: Vec::new(),
        answers: Vec::new(),
        questions: Vec::new(),
        questions_dropped: 0,
        last_seen: Instant::now(),
        is_active: true,
        last_event: None,
    };
    lonely.answers.push(raw_record(
        "Lonely._http._tcp.local.",
        33,
        "SRV",
        "0 0 0 .",
        120,
    ));
    app.services.push(lonely);
    ingest_packet(
        &mut app,
        event_for(&raw_record("test.local.", 1, "A", "192.168.1.10", 120)),
    );
    ingest_packet(&mut app, event_for(&ptr_record(120)));
    ingest_packet(&mut app, event_for(&srv_record(120)));
    let lonely = service_of(&app, "Lonely");
    assert!(lonely.answers.iter().all(|r| r.rtype != 1));
    assert!(service_of(&app, "Test")
        .answers
        .iter()
        .any(|r| r.rtype == 1));
}

#[test]
fn enumeration_rows_long_past_ttl_are_pruned_txt_kept_expanded() {
    let Some(old) = Instant::now().checked_sub(Duration::from_secs(200)) else {
        return; // host clock too young to backdate
    };
    let mut app = App::new().unwrap();
    let mut stale = raw_record(ENUM_SERVICE, 12, "PTR", "_http._tcp.local.", 10);
    stale.received_at = old;
    let txt = raw_record(ENUM_SERVICE, 16, "TXT", "note=1", 4500);
    app.expanded_txt.insert(App::txt_key(&txt));
    app.enum_entries[0].answers = vec![stale, txt.clone()];
    let gen = app.state_gen;
    app.evict_expired();
    let left: Vec<_> = app.enum_entries[0]
        .answers
        .iter()
        .map(|r| r.rtype)
        .collect();
    assert_eq!(left, [16], "the stale PTR went, the live TXT stayed");
    assert_ne!(app.state_gen, gen, "the view was told");
    assert!(
        app.is_txt_expanded(&txt),
        "a live enum TXT keeps its expansion"
    );
}

#[test]
fn names_fold_ascii_case_only_per_rfc_6762_section_16() {
    // A-Z match a-z; every other byte compares exactly, so `É`
    // (U+00C9) and `é` (U+00E9) name different instances and hosts.
    let mut app = App::new().unwrap();
    for (instance, host) in [
        ("\u{00C9}clair", "\u{00C9}vent.local."),
        ("\u{00E9}clair", "\u{00E9}vent.local."),
    ] {
        let full = format!("{instance}._http._tcp.local.");
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", &full, 120),
        );
        ingest(
            &mut app,
            &raw_record(&full, 33, "SRV", &format!("0 0 80 {host}"), 120),
        );
    }
    // Another ASCII case of the first name is the same instance.
    ingest(
        &mut app,
        &raw_record("\u{00C9}CLAIR._HTTP._tcp.local.", 16, "TXT", "a=1", 120),
    );
    app.evict_expired();
    let mut instances: Vec<&str> = app.services.iter().map(|s| s.instance.as_str()).collect();
    instances.sort();
    assert_eq!(instances, ["\u{00C9}clair", "\u{00E9}clair"]);
    let upper = app
        .services
        .iter()
        .find(|s| s.instance == "\u{00C9}clair")
        .unwrap();
    assert!(
        upper.answers.iter().any(|r| r.rtype == 16),
        "TXT filed on \u{00C9}clair"
    );
    let groups: Vec<String> = app
        .group_labels()
        .into_iter()
        .filter(|l| l.ends_with("vent.local"))
        .collect();
    assert_eq!(groups.len(), 2, "two hosts: {groups:?}");
}

/// `avahi-publish-service Á.a _test._tcp 443`: one instance label that
/// holds a dot. Its display name `Á.a._test._tcp.local.` can't tell the
/// label boundary; the wire labels can.
fn dotted_instance_record(rtype: u16, rtype_str: &str, rdata: &str) -> browse::RawRecord {
    let mut rec = raw_record("Á.a._test._tcp.local.", rtype, rtype_str, rdata, 120);
    rec.owner_labels = ["Á.a", "_test", "_tcp", "local"]
        .iter()
        .map(|label| label.as_bytes().to_vec())
        .collect();
    rec
}

#[test]
fn srv_before_ptr_keeps_dotted_instance_label() {
    let mut app = App::new().unwrap();
    let mut srv = dotted_instance_record(33, "SRV", "0 0 443 host.local.");
    srv.flush_bit = true;
    ingest(&mut app, &srv);
    assert_eq!(app.services.len(), 1);
    assert_eq!(app.services[0].instance, "Á.a");
    assert_eq!(app.services[0].service_type, "_test._tcp.local");
    assert!(findings_of(&app, anomalies::AnomalyKind::TypeFormat).is_empty());
}

#[test]
fn txt_before_ptr_keeps_dotted_instance_label() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &dotted_instance_record(16, "TXT", "uga=http://uga.bung"),
    );
    assert_eq!(app.pending_instances.len(), 1);
    assert_eq!(app.pending_instances[0].instance, "Á.a");
    assert_eq!(app.pending_instances[0].service_type, "_test._tcp.local");
}

#[test]
fn owner_without_wire_labels_falls_back_to_display_split() {
    let app = App::new().unwrap();
    let mut rec = raw_record("Test._http._tcp.local.", 33, "SRV", "0 0 80 t.local.", 120);
    rec.owner_labels.clear();
    assert_eq!(
        app.split_owner(&rec),
        Some(("Test".to_string(), "_http._tcp.local".to_string()))
    );
    rec.owner_labels = vec![b"local".to_vec()];
    assert_eq!(app.split_owner(&rec), None);
}
