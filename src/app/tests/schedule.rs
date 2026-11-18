// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn known_answers_carry_their_ingress_interface() {
    let mut app = App::new().unwrap();
    let mut a = ptr_record(120);
    a.iface = "br0".to_string();
    ingest(&mut app, &a);
    // Same instance seen on another link: distinct source, distinct row.
    let mut b = ptr_record(120);
    b.iface = "enx".to_string();
    b.source = "192.168.178.61:5353".parse().unwrap();
    ingest(&mut app, &b);
    ingest(&mut app, &srv_record(120));
    let mut ifaces: Vec<String> = app
        .known_ptrs("_http._tcp.local")
        .into_iter()
        .map(|ka| ka.iface)
        .collect();
    ifaces.sort();
    assert_eq!(ifaces, vec!["br0".to_string(), "enx".to_string()]);
}

#[test]
fn huge_ttl_ptr_is_a_known_answer_without_overflow() {
    // A responder may announce any 32-bit TTL; the half-TTL check must
    // not overflow (debug builds panicked here).
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(u32::MAX));
    ingest(&mut app, &srv_record(120));
    let kas = app.known_ptrs("_http._tcp.local");
    assert_eq!(kas.len(), 1, "a fresh huge-TTL PTR is still a known answer");
}

#[test]
fn huge_ttl_enumeration_answer_is_a_known_answer_without_overflow() {
    let mut app = App::new().unwrap();
    let mut rec = ptr_record(u32::MAX);
    rec.name = "_services._dns-sd._udp.local.".to_string();
    rec.rdata = "_http._tcp.local.".to_string();
    app.scheduler.note_enum_type("_http._tcp.local", &rec);
    let kas = app.known_enum_answers();
    assert_eq!(kas.len(), 1);
    assert_eq!(kas[0].target, "_http._tcp.local");
}

#[test]
fn hostname_case_preserved_in_queries() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(
        &mut app,
        &raw_record(
            "Test._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 MyHost.local.",
            120,
        ),
    );
    // Dedup keys stay lowercase, but the query name keeps wire case.
    let desired = app.desired_continuous();
    let qname = desired
        .get(&("myhost.local".to_string(), 1))
        .expect("A query interest for the host");
    assert_eq!(qname.trim_end_matches('.'), "MyHost.local");
    let qname_aaaa = desired
        .get(&("myhost.local".to_string(), 28))
        .expect("AAAA query interest for the host");
    assert_eq!(qname_aaaa.trim_end_matches('.'), "MyHost.local");
}

#[test]
fn cached_unique_address_skips_initial_query() {
    let mut app = App::new().unwrap();
    ingest_srv_with_addresses(&mut app, true);
    app.poll_continuous();
    for rtype in [1, 28] {
        let entry = app
            .scheduler
            .continuous()
            .get(&("test.local".to_string(), rtype))
            .expect("address interest");
        assert_eq!(entry.interval, MAX_CONTINUOUS_INTERVAL);
        assert!(entry.next_due > Instant::now() + Duration::from_secs(3500));
    }
}

#[test]
fn cached_unique_txt_of_a_pending_instance_skips_initial_query() {
    // PTR and a unique TXT, no SRV yet: the instance stays pending, but
    // its TXT interest already has a fresh unique answer (RFC 6762 §5.2).
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    let mut txt = txt_record("a=1");
    txt.flush_bit = true;
    ingest(&mut app, &txt);
    assert!(
        app.services.is_empty(),
        "no SRV: the instance is still pending"
    );
    app.poll_continuous();
    let entry = app
        .scheduler
        .continuous()
        .get(&("test._http._tcp.local".to_string(), 16))
        .expect("TXT interest of the pending instance");
    assert_eq!(entry.interval, MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn dampened_address_interest_stays_visible() {
    let mut app = App::new().unwrap();
    ingest_srv_with_addresses(&mut app, true);
    app.poll_continuous();
    let svc = app
        .services
        .iter()
        .find(|s| s.hostname.trim_end_matches('.') == "test.local")
        .expect("service");
    for label in ["A", "AAAA"] {
        assert!(
            svc.questions
                .iter()
                .any(|q| q.0 == "test.local." && q.1 == label && q.2 == SELF_SOURCE),
            "{label} interest must show as a pending self row"
        );
    }
    // Nothing was sent: no transmitted or suppressed event, and the
    // refresh owns DUE.
    let s = app.interest_summary("test.local", 1);
    assert!(s.last_transmitted_at.is_none());
    assert!(s.last_suppressed_at.is_none());
    assert_eq!(s.timer, TimerKind::Refresh);
    assert!(s.next_due_in_secs.is_some());
}

#[test]
fn missing_address_still_queried_promptly() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    app.poll_continuous();
    for rtype in [1, 28] {
        let entry = app
            .scheduler
            .continuous()
            .get(&("test.local".to_string(), rtype))
            .expect("address interest");
        assert_eq!(entry.interval, Duration::from_secs(1));
        assert!(entry.next_due <= Instant::now() + Duration::from_millis(120));
    }
}

#[test]
fn shared_cached_answer_does_not_dampen() {
    let mut app = App::new().unwrap();
    ingest_srv_with_addresses(&mut app, false);
    app.poll_continuous();
    let entry = app
        .scheduler
        .continuous()
        .get(&("test.local".to_string(), 1))
        .expect("address interest");
    assert_eq!(entry.interval, Duration::from_secs(1));
}

#[test]
fn huge_ttl_unique_answer_does_not_overflow() {
    let mut app = App::new().unwrap();
    ingest_srv_with_addresses(&mut app, true);
    cached_a_row(&mut app).ttl = u32::MAX;
    assert!(app.has_fresh_unique_answer(&Scheduler::continuous_key("test.local", 1)));
}

#[test]
fn unique_answer_matches_non_ascii_case() {
    let mut app = App::new().unwrap();
    ingest_srv_with_addresses(&mut app, true);
    cached_a_row(&mut app).name = "Étage.local.".to_string();
    assert!(app.has_fresh_unique_answer(&Scheduler::continuous_key("étage.local", 1)));
}

#[test]
fn enum_gets_qu_on_first_send() {
    let mut app = App::new().unwrap();
    app.poll_continuous(); // seeds the enumeration interest
    let past = Instant::now() - Duration::from_millis(1);
    app.scheduler
        .continuous_mut()
        .get_mut(&(ENUM_SERVICE.to_string().to_lowercase(), 12))
        .expect("enum interest seeded")
        .next_due = past;
    app.poll_continuous();
    assert_eq!(app.metrics.qu_sent, 1);
    assert_eq!(app.metrics.q_sent_continuous, 1);
}

#[test]
fn continuous_backoff_is_1s_then_doubling() {
    let mut app = App::new().unwrap();
    app.scheduler
        .known_types_mut()
        .insert("_http._tcp.local".to_string());
    let key = ("_http._tcp.local".to_string(), 12);
    app.scheduler.continuous_mut().insert(
        key.clone(),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(1),
            qname: "_http._tcp.local".to_string(),
        },
    );
    app.poll_continuous();
    let entry = app
        .scheduler
        .continuous()
        .get(&key)
        .expect("still scheduled");
    assert_eq!(entry.interval, Duration::from_secs(2));
    // First gap uses the 1s interval, not the doubled 2s.
    assert!(entry.next_due > Instant::now() + Duration::from_millis(500));
    assert!(entry.next_due <= Instant::now() + Duration::from_secs(1));

    // Second gap uses the 2s interval, then doubles to 4s.
    app.scheduler
        .continuous_mut()
        .get_mut(&key)
        .unwrap()
        .next_due = Instant::now() - Duration::from_millis(1);
    app.poll_continuous();
    let entry = app
        .scheduler
        .continuous()
        .get(&key)
        .expect("still scheduled");
    assert_eq!(entry.interval, Duration::from_secs(4));
    assert!(entry.next_due > Instant::now() + Duration::from_secs(1));
    assert!(entry.next_due <= Instant::now() + Duration::from_secs(2));
}

#[test]
fn huge_ttl_does_not_overflow_refresh_window() {
    // TTLs come unbounded from the wire; caching and refreshing a
    // record with TTL >= 2^30 s must not overflow (debug panic).
    assert!(!in_refresh_window(0, u32::MAX));
    assert!(in_refresh_window(u32::MAX, u32::MAX));
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(u32::MAX));
    ingest(&mut app, &srv_record(u32::MAX));
    ingest(&mut app, &srv_record(u32::MAX));
    app.requery_expiring();
}

#[test]
fn refresh_step_has_no_1s_floor() {
    // TTL 120: classic 6s + 0-2.4s jitter.
    assert_eq!(refresh_step(120, 0), Duration::from_millis(6000));
    assert_eq!(refresh_step(120, 200), Duration::from_millis(8400));
    // TTL 10: 0.5s + 0-0.2s must stay sub-second so the 85/90/95%
    // windows are still reachable; the old 1s floor pushed them
    // past 100%.
    assert_eq!(refresh_step(10, 0), Duration::from_millis(500));
    assert_eq!(refresh_step(10, 200), Duration::from_millis(700));
}

#[test]
fn requery_ignores_expired_rows() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    // Age the PTR past 100% TTL: no live row remains for the key.
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 12 {
                rec.received_at = Instant::now() - Duration::from_secs(130);
            }
        }
    }
    app.requery_expiring();
    let key = ("_http._tcp.local".to_string(), 12);
    assert!(
        !app.scheduler.requeries().contains_key(&key),
        "expired rows must not schedule refresh queries"
    );
}

#[test]
fn stale_row_gets_four_refreshes_then_stops() {
    let mut app = app_with_stale_enum_row();
    for _ in 0..12 {
        app.requery_expiring();
        make_refresh_due(&mut app, "_services._dns-sd._udp.local", 12);
    }
    assert_eq!(
        app.metrics.q_sent_refresh, 4,
        "after four misses the row expires at 100%; no new cycle"
    );
}

#[test]
fn refresh_step_follows_the_triggering_row_ttl() {
    let mut app = app_with_stale_enum_row();
    app.requery_expiring();
    let key = ("_services._dns-sd._udp.local".to_string(), 12);
    let (due, count) = app.scheduler.requeries_mut()[&key];
    assert_eq!(count, 1);
    // 5% of the stale row's 4500s TTL, not of the sibling's 60s.
    assert!(
        due >= Instant::now() + Duration::from_secs(200),
        "step must come from the row inside its refresh window"
    );
}

#[test]
fn new_answer_rearms_a_spent_row() {
    let mut app = app_with_stale_enum_row();
    for _ in 0..6 {
        app.requery_expiring();
        make_refresh_due(&mut app, "_services._dns-sd._udp.local", 12);
    }
    assert_eq!(app.metrics.q_sent_refresh, 4);
    // The responder re-announces late, then that row ages into its
    // window again: it is a new row and gets its own refresh cycle.
    let row = app.enum_entries[0]
        .answers
        .iter_mut()
        .find(|r| r.ttl == 4500)
        .unwrap();
    row.received_at = Instant::now() - Duration::from_secs(3700);
    app.requery_expiring();
    assert_eq!(app.metrics.q_sent_refresh, 5);
}

#[test]
fn shared_address_row_counts_one_attempt_per_query() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    ingest(
        &mut app,
        &raw_record(
            "_http._tcp.local.",
            12,
            "PTR",
            "Other._http._tcp.local.",
            120,
        ),
    );
    let mut srv = raw_record(
        "Other._http._tcp.local.",
        33,
        "SRV",
        "0 0 81 test.local.",
        120,
    );
    srv.flush_bit = true;
    ingest(&mut app, &srv);
    let mut addr = raw_record("test.local.", 1, "A", "192.168.1.2", 120);
    addr.flush_bit = true;
    ingest(&mut app, &addr);
    // One host backs both services: the same A row is filed twice.
    let aged = Instant::now() - Duration::from_secs(100);
    let mut copies = 0;
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 1 {
                rec.received_at = aged;
                copies += 1;
            }
        }
    }
    assert_eq!(copies, 2);
    for _ in 0..8 {
        app.requery_expiring();
        make_refresh_due(&mut app, "test.local", 1);
    }
    assert_eq!(app.metrics.q_sent_refresh, 4);
}

#[test]
fn newly_due_sibling_is_not_held_by_a_pending_deadline() {
    let mut app = App::new().unwrap();
    app.enum_entries[0]
        .answers
        .push(enum_row("_ipp._tcp.local.", 4500, "192.168.1.4:5353", 3600));
    app.requery_expiring();
    assert_eq!(app.metrics.q_sent_refresh, 1);
    // A TTL 60 sibling reaches 80% while the 4500s row's next attempt
    // is ~225s away: it must be asked about in its own window.
    app.enum_entries[0]
        .answers
        .push(enum_row("_http._tcp.local.", 60, "192.168.1.3:5353", 48));
    app.requery_expiring();
    assert_eq!(app.metrics.q_sent_refresh, 2);
}

#[test]
fn late_sibling_gets_its_own_four_attempts() {
    let mut app = App::new().unwrap();
    app.enum_entries[0]
        .answers
        .push(enum_row("_ipp._tcp.local.", 100, "192.168.1.4:5353", 80));
    let key = "_services._dns-sd._udp.local";
    for _ in 0..3 {
        app.requery_expiring();
        make_refresh_due(&mut app, key, 12);
    }
    assert_eq!(app.metrics.q_sent_refresh, 3);
    // The sibling enters its window just before the first row's
    // fourth attempt; that shared query is only its first.
    app.enum_entries[0]
        .answers
        .push(enum_row("_http._tcp.local.", 100, "192.168.1.3:5353", 80));
    for _ in 0..8 {
        app.requery_expiring();
        make_refresh_due(&mut app, key, 12);
    }
    assert_eq!(app.metrics.q_sent_refresh, 7);
}

#[test]
fn spent_rows_are_not_projected_as_due() {
    let mut app = app_with_stale_enum_row();
    for _ in 0..6 {
        app.requery_expiring();
        make_refresh_due(&mut app, "_services._dns-sd._udp.local", 12);
    }
    assert_eq!(app.metrics.q_sent_refresh, 4);
    let key = ("_services._dns-sd._udp.local".to_string(), 12);
    assert!(!app.scheduler.requeries().contains_key(&key));
    // Only the fresh TTL 60 row is left to refresh, at 80% (48s).
    let due = app.next_refresh_due(&key).expect("fresh row projected");
    assert!(due >= Instant::now() + Duration::from_secs(40));
}

#[test]
fn query_provenance_records_transmit_suppress_observe() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    // Age the SRV into the refresh window so a refresh is due.
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 33 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    app.requery_expiring();
    // No overheard query: the SRV refresh is transmitted.
    let srv_key = ("test._http._tcp.local".to_string(), 33);
    let prov = app
        .scheduler
        .query_history()
        .get(&srv_key)
        .expect("provenance recorded");
    assert!(prov.transmitted.is_some());
    assert!(matches!(
        prov.last().map(|(o, _)| o),
        Some(QueryOrigin::Transmitted)
    ));

    // A remote QM question for the same key suppresses the next
    // refresh (§7.3): the KA set is empty on both sides.
    let ev = query_event(
        "Test._http._tcp.local.",
        33,
        "SRV",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    let prov = app
        .scheduler
        .query_history()
        .get(&srv_key)
        .expect("observed recorded");
    assert!(prov.observed.is_some());
    // Make the refresh due again: the schedule spaces attempts ~5%
    // of TTL apart, so without backdating the second run skips it.
    make_refresh_due(&mut app, "Test._http._tcp.local", 33);
    app.requery_expiring();
    let prov = app
        .scheduler
        .query_history()
        .get(&srv_key)
        .expect("still there");
    assert!(prov.suppressed.is_some());
    assert!(matches!(
        prov.last().map(|(o, _)| o),
        Some(QueryOrigin::Suppressed)
    ));

    // An unrelated observed question records observation only.
    let ev = query_event(
        "_printer._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    let prov = app
        .scheduler
        .query_history()
        .get(&("_printer._tcp.local".to_string(), 12))
        .expect("observed recorded");
    assert!(prov.observed.is_some());
    assert!(prov.transmitted.is_none());
    assert!(prov.suppressed.is_none());
}

#[test]
fn query_provenance_prunes_dead_interests() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    // Recent provenance for a live interest survives eviction.
    app.note_query(
        "_http._tcp.local",
        12,
        QueryOrigin::Transmitted,
        Instant::now(),
    );
    // Stale provenance with no live schedule is dropped.
    app.scheduler.query_history_mut().insert(
        ("gone._tcp.local".to_string(), 12),
        InterestQueryState {
            transmitted: Some(Instant::now() - Duration::from_secs(3600)),
            ..Default::default()
        },
    );
    app.evict_expired();
    assert!(app
        .scheduler
        .query_history()
        .contains_key(&("_http._tcp.local".to_string(), 12)));
    assert!(!app
        .scheduler
        .query_history()
        .contains_key(&("gone._tcp.local".to_string(), 12)));
}

#[test]
fn interest_view_reports_timer_and_status() {
    let mut app = App::new().unwrap();
    // Unknown interest: no schedule, no answers, no history.
    let view = app.interest_view(&("_http._tcp.local".to_string(), 12));
    assert_eq!(view.timer, TimerKind::Expired);
    assert_eq!(view.status, InterestStatus::Abandoned);
    assert_eq!(view.attempt, 0);
    assert!(view.next_due.is_none());
    assert!(view.origin().is_none());

    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    // Continuous stream exists after a poll; no refresh due yet.
    app.poll_continuous();
    let view = app.interest_view(&("_http._tcp.local".to_string(), 12));
    assert_eq!(view.timer, TimerKind::Browse);
    assert!(view.next_due.is_some());
    // Live answers, nothing pending: answered.
    assert_eq!(view.status, InterestStatus::Answered);

    // Age the SRV into the refresh window: the refresh timer wins
    // over the continuous stream and the send is recorded.
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 33 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    app.requery_expiring();
    let view = app.interest_view(&("test._http._tcp.local".to_string(), 33));
    assert_eq!(view.timer, TimerKind::Refresh);
    assert_eq!(view.status, InterestStatus::Transmitted);
    assert_eq!(view.attempt, 1);
    assert_eq!(view.origin(), Some(QueryOrigin::Transmitted));
}

#[test]
fn pihole_cycle_expires_after_four_misses_then_rescues() {
    // Regression fixture for the observed Pi-hole sequence: repeated
    // 120s SRV records expiring after unanswered refreshes, then
    // renewed when another browse elicits the SRV as additional data.
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let age_srv = |app: &mut App, secs: u64| {
        for svc in &mut app.services {
            for rec in &mut svc.answers {
                if rec.rtype == 33 {
                    rec.received_at = Instant::now() - Duration::from_secs(secs);
                }
            }
        }
    };
    age_srv(&mut app, 100);
    // Four unanswered refreshes: attempts 1-3 stay pending, the
    // fourth expires the schedule.
    for expected in 1u8..=4u8 {
        make_refresh_due(&mut app, "Test._http._tcp.local", 33);
        app.requery_expiring();
        if expected < 4 {
            let view = app.interest_view(&("test._http._tcp.local".to_string(), 33));
            assert_eq!(view.status, InterestStatus::Transmitted);
            assert_eq!(view.attempt, expected);
        }
    }
    assert!(!app
        .scheduler
        .requeries()
        .keys()
        .any(|(n, t)| n == "Test._http._tcp.local" && *t == 33));
    assert_eq!(app.metrics.q_sent_refresh, 4);
    // Row past TTL with no pending refresh: abandoned, while the
    // continuous stream stays live for hourly rediscovery (§5.2).
    age_srv(&mut app, 130);
    let key = ("test._http._tcp.local".to_string(), 33);
    let view = app.interest_view(&key);
    assert_eq!(view.timer, TimerKind::Browse);
    assert_eq!(view.status, InterestStatus::Abandoned);
    // Another browser's PTR browse rescues the SRV as additional
    // data: fresh row, no false self query, provenance intact.
    let questions_before: usize = app.services.iter().map(|s| s.questions.len()).sum();
    let mut rescue = event_for(&srv_record(120));
    rescue.source = remote_source();
    for rec in &mut rescue.answers {
        rec.source = remote_source();
    }
    app.ingest_event(&rescue);
    let view = app.interest_view(&key);
    assert_eq!(view.status, InterestStatus::Answered);
    assert_eq!(view.attempt, 0);
    assert_eq!(view.origin(), Some(QueryOrigin::Transmitted));
    let questions_after: usize = app.services.iter().map(|s| s.questions.len()).sum();
    assert_eq!(questions_before, questions_after);
}

#[test]
fn provenance_lookup_folds_non_ascii_case() {
    let mut app = App::new().unwrap();
    // A requery entry keyed in wire case (U+00C9 É, U+00E9 é) must
    // be found through its lowercase form (U+00E9 é): explicit
    // code points keep the test independent of the editor's
    // composed/decomposed accent handling, which to_lowercase does
    // not normalize away.
    let wire_case = "\u{00C9}tag\u{00E9}._http._tcp.local";
    let lower_case = "\u{00E9}tag\u{00E9}._http._tcp.local";
    app.scheduler.requeries_mut().insert(
        (wire_case.to_string(), 12),
        (Instant::now() + Duration::from_secs(60), 2),
    );
    let view = app.interest_view(&(lower_case.to_string(), 12));
    assert_eq!(view.timer, TimerKind::Refresh);
    assert_eq!(view.attempt, 2);
}

#[test]
fn projected_refresh_beats_backed_off_browse() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    app.poll_continuous();
    // Back the continuous stream off to hourly: the projected
    // refresh at receipt + 80% TTL must own DUE instead.
    let key = ("test._http._tcp.local".to_string(), 33);
    app.scheduler
        .continuous_mut()
        .get_mut(&key)
        .unwrap()
        .next_due = Instant::now() + Duration::from_secs(3600);
    let view = app.interest_view(&key);
    assert_eq!(view.timer, TimerKind::Refresh);
    let secs = view
        .next_due
        .unwrap()
        .saturating_duration_since(Instant::now())
        .as_secs();
    assert!((90..=96).contains(&secs), "due {secs}s out of window");
}

#[test]
fn passive_browser_projects_no_refresh() {
    let mut app = App::new_with(true, None).unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    // Live answers, but a passive browser transmits nothing: no
    // schedule, no projection, no false refresh countdown.
    let view = app.interest_view(&("test._http._tcp.local".to_string(), 33));
    assert_eq!(view.timer, TimerKind::Expired);
    assert_eq!(view.status, InterestStatus::Answered);
    assert!(view.next_due.is_none());
}

#[test]
fn requery_postpones_continuous_for_same_key() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    // Age PTR into the 80-100% window so a refresh is due.
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 12 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    // Continuous stream is due right now.
    let ckey = ("_http._tcp.local".to_string(), 12);
    app.scheduler.continuous_mut().insert(
        ckey.clone(),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(2),
            qname: "_http._tcp.local".to_string(),
        },
    );
    app.requery_expiring();
    let entry = app
        .scheduler
        .continuous()
        .get(&ckey)
        .expect("still scheduled");
    // Refresh sent now, so the exponential stream must wait at
    // least its interval instead of firing on the same tick.
    assert!(entry.next_due > Instant::now() + Duration::from_millis(500));
}

#[test]
fn duplicate_qm_with_subset_ka_suppresses_continuous() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let ckey = ("_http._tcp.local".to_string(), 12);
    app.scheduler.continuous_mut().insert(
        ckey.clone(),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(2),
            qname: "_http._tcp.local".to_string(),
        },
    );
    // Remote asks the same QM question with a KA subset (empty ⊆ ours).
    let ev = query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    app.poll_continuous();
    let entry = app
        .scheduler
        .continuous()
        .get(&ckey)
        .expect("still scheduled");
    // Treated as sent: backed off instead of transmitting.
    assert_eq!(entry.interval, Duration::from_secs(4));
    assert!(entry.next_due > Instant::now() + Duration::from_secs(1));
    // Single-use: entry consumed.
    assert!(!app
        .scheduler
        .overheard()
        .contains_key(&("_http._tcp.local".to_string(), 12)));
}

#[test]
fn duplicate_qm_with_extra_ka_does_not_suppress() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let ckey = ("_http._tcp.local".to_string(), 12);
    app.scheduler.continuous_mut().insert(
        ckey.clone(),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(2),
            qname: "_http._tcp.local".to_string(),
        },
    );
    // Remote KA holds a target we don't know — must not suppress.
    let ev = query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        vec![ka_record("_http._tcp.local.", "Other._http._tcp.local.")],
        remote_source(),
    );
    app.ingest_event(&ev);
    app.poll_continuous();
    let entry = app
        .scheduler
        .continuous()
        .get(&ckey)
        .expect("still scheduled");
    assert_eq!(entry.interval, Duration::from_secs(4));
    // Not suppressed: next_due is now+2s from the real send, but the
    // overheard entry remains since it wasn't consumed.
    assert!(app
        .scheduler
        .overheard()
        .contains_key(&("_http._tcp.local".to_string(), 12)));
}

#[test]
fn qu_and_local_source_never_suppress() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let ckey = ("_http._tcp.local".to_string(), 12);
    app.scheduler.continuous_mut().insert(
        ckey.clone(),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(2),
            qname: "_http._tcp.local".to_string(),
        },
    );
    // QU bit set: not a QM question.
    let ev = query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        true,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    assert!(app.scheduler.overheard().is_empty());
    // Loopback from ourselves: ignored even with subset KA.
    let local: std::net::SocketAddr = test_source();
    app.local_ips.insert(local.ip());
    let ev = query_event("_http._tcp.local.", 12, "PTR", false, Vec::new(), local);
    app.ingest_event(&ev);
    assert!(app.scheduler.overheard().is_empty());
}

#[test]
fn active_mode_sends_due_queries() {
    let mut app = due_query_setup();
    app.send_queries();
    assert_eq!(app.metrics.q_sent_refresh, 1);
    // The refresh postpones the continuous twin for the same key
    // instead of emitting back-to-back duplicates.
    assert_eq!(app.metrics.q_sent_continuous, 0);
    let entry = app
        .scheduler
        .continuous()
        .get(&("_http._tcp.local".to_string(), 12))
        .expect("still scheduled");
    assert!(entry.next_due > Instant::now());
}

#[test]
fn passive_mode_sends_nothing() {
    let setup = due_query_setup();
    let due = setup
        .scheduler
        .continuous()
        .get(&("_http._tcp.local".to_string(), 12))
        .expect("seeded entry")
        .next_due;
    let mut app = setup;
    app.passive = true;
    app.send_queries();
    let entry = app
        .scheduler
        .continuous()
        .get(&("_http._tcp.local".to_string(), 12))
        .expect("still scheduled");
    assert_eq!(entry.next_due, due);
    assert_eq!(entry.interval, Duration::from_secs(2));
    assert_eq!(app.metrics.q_sent_continuous, 0);
    assert_eq!(app.metrics.q_sent_refresh, 0);
    assert!(app.scheduler.requeries().is_empty());
    assert!(!*app.scheduler.startup_qu_sent_mut());
}

#[test]
fn passive_constructor_sets_flag() {
    assert!(!App::new().unwrap().passive);
    assert!(App::new_with(true, None).unwrap().passive);
}

#[test]
fn query_interfaces_survive_link_changes_and_exclude_inactive_selection() {
    let mut app = App::new().unwrap();
    app.interfaces = Some(
        ["br0".to_string(), "down0".to_string()]
            .into_iter()
            .collect(),
    );
    app.link_stats.v4 = vec![("br0".into(), "192.168.1.2".parse().unwrap())];
    app.link_stats.v6.clear();
    app.note_query("test.local", 1, QueryOrigin::Transmitted, Instant::now());
    app.link_stats.v4.clear();
    app.interfaces = None;
    assert_eq!(
        app.scheduler.query_history_mut()[&Scheduler::provenance_key("test.local", 1)]
            .transmitted_interfaces,
        "br0"
    );
}

/// Ingest PTR + SRV + A/AAAA as one response packet (addresses as
/// additionals), with the given cache-flush bit on the addresses.
fn ingest_srv_with_addresses(app: &mut App, addr_flush: bool) {
    let mut a = raw_record("test.local.", 1, "A", "192.168.1.10", 120);
    a.flush_bit = addr_flush;
    let mut aaaa = raw_record("test.local.", 28, "AAAA", "fe80::1", 120);
    aaaa.flush_bit = addr_flush;
    let mut ev = event_for(&ptr_record(4500));
    ev.answers.extend([srv_record(120), a, aaaa]);
    ingest_packet(app, ev);
}

/// Mutable access to the cached A row of the test service.
fn cached_a_row(app: &mut App) -> &mut browse::RawRecord {
    app.services
        .iter_mut()
        .flat_map(|s| s.answers.iter_mut())
        .find(|r| r.rtype == 1)
        .expect("cached A row")
}
