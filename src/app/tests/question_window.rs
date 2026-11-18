// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #238: Questions rows age out by a time window ---

use super::*;

#[test]
fn question_rows_age_out_after_the_window_without_counting_as_drops() {
    let mut app = test_service_app();
    let (old, recent) = (querier(1), querier(2));
    ask(&mut app, "Test._http._tcp.local.", old);
    ask(&mut app, "Test._http._tcp.local.", recent);
    age_questions(&mut app, old, PAST_WINDOW);
    age_questions(&mut app, recent, QUESTION_WINDOW.as_secs() - 60);
    app.evict_expired();
    assert_eq!(dumped_sources(&app), vec![recent.to_string()]);
    let dump = app.state_dump();
    assert!(
        !dump.services[0].questions_truncated,
        "ageing is not truncation"
    );
    assert_eq!(dump.services[0].questions_dropped, 0);
    assert_eq!(dump.question_window_secs, 4500);
}

#[test]
fn a_reask_refreshes_the_row() {
    let mut app = test_service_app();
    let q = querier(1);
    ask(&mut app, "Test._http._tcp.local.", q);
    age_questions(&mut app, q, PAST_WINDOW);
    ask(&mut app, "Test._http._tcp.local.", q);
    app.evict_expired();
    assert_eq!(dumped_sources(&app), vec![q.to_string()]);
}

#[test]
fn more_than_ten_queriers_inside_the_window_all_stay() {
    let mut app = test_service_app();
    for i in 0..25 {
        ask(&mut app, "Test._http._tcp.local.", querier(i));
    }
    app.evict_expired();
    assert_eq!(dumped_sources(&app).len(), 25);
    assert!(!app.state_dump().services[0].questions_truncated);
}

#[test]
fn self_rows_follow_the_same_window() {
    let mut app = test_service_app();
    app.route_own_question("Test._http._tcp.local.", 16, false);
    assert_eq!(dumped_sources(&app), vec![SELF_SOURCE_LABEL.to_string()]);
    // Re-sent at the normal cadence: the row stays.
    age_questions(&mut app, SELF_SOURCE, QUESTION_WINDOW.as_secs() - 60);
    app.evict_expired();
    assert_eq!(dumped_sources(&app).len(), 1);
    // Not asked for longer than the window: gone.
    age_questions(&mut app, SELF_SOURCE, PAST_WINDOW);
    app.evict_expired();
    assert!(dumped_sources(&app).is_empty());
}

#[test]
fn enumeration_questions_age_out_too() {
    let mut app = App::new().unwrap();
    let q = querier(1);
    app.ingest_event(&query_event(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        q,
    ));
    let listed = |app: &App| -> usize {
        app.state_dump()
            .enum_groups
            .iter()
            .map(|g| g.questions.len())
            .sum()
    };
    assert_eq!(listed(&app), 1);
    age_questions(&mut app, q, PAST_WINDOW);
    app.evict_expired();
    assert_eq!(listed(&app), 0);
}

#[test]
fn promotion_keeps_parked_rows_and_carries_cap_drops() {
    let mut app = App::new().unwrap();
    // PTR without SRV: a pending instance. Only our own sends file
    // question rows there.
    ingest(&mut app, &ptr_record(4500));
    app.route_own_question("Test._http._tcp.local.", 16, false);
    assert_eq!(app.pending_instances[0].questions.len(), 1);
    age_questions(&mut app, SELF_SOURCE, 600);
    // Cap drops recorded while parked carry over on promotion.
    app.pending_instances[0].questions_dropped = 3;
    ingest(&mut app, &srv_record(120));
    app.evict_expired();
    let dump = app.state_dump();
    let svc = &dump.services[0];
    let row = svc
        .questions
        .iter()
        .find(|q| q.source == SELF_SOURCE_LABEL)
        .expect("parked row kept");
    assert!(row.age_secs >= 600, "seen-at kept: {}", row.age_secs);
    assert_eq!(svc.questions_dropped, 3);
    assert!(svc.questions_truncated);
}

#[test]
fn expired_rows_never_cost_a_live_row_its_slot() {
    let mut app = test_service_app();
    for i in 0..QUESTION_CAP {
        ask(&mut app, "Test._http._tcp.local.", querier(i));
    }
    // A long pause: every row is past the window, none pruned yet.
    for i in 0..QUESTION_CAP {
        age_questions(&mut app, querier(i), PAST_WINDOW);
    }
    // The first querier re-asks, then a new one arrives.
    ask(&mut app, "Test._http._tcp.local.", querier(0));
    ask(&mut app, "Test._http._tcp.local.", querier(500));
    app.evict_expired();
    let mut got = dumped_sources(&app);
    got.sort();
    let mut want = vec![querier(0).to_string(), querier(500).to_string()];
    want.sort();
    assert_eq!(got, want);
    let dump = app.state_dump();
    assert_eq!(
        dump.services[0].questions_dropped, 0,
        "ageing is not a drop"
    );
}

#[test]
fn a_full_live_list_evicts_its_stalest_row() {
    let mut app = test_service_app();
    for i in 0..QUESTION_CAP {
        ask(&mut app, "Test._http._tcp.local.", querier(i));
        // Older rows first: querier(0) is the stalest...
        age_questions(&mut app, querier(i), 1000 - i as u64);
    }
    // ...until it re-asks; querier(1) is now the stalest.
    ask(&mut app, "Test._http._tcp.local.", querier(0));
    ask(&mut app, "Test._http._tcp.local.", querier(500));
    let got = dumped_sources(&app);
    assert!(got.contains(&querier(0).to_string()), "re-asked row kept");
    assert!(got.contains(&querier(500).to_string()));
    assert!(!got.contains(&querier(1).to_string()), "stalest evicted");
    assert_eq!(app.state_dump().services[0].questions_dropped, 1);
}

/// Backdate every question row from `source` by `secs`.
fn age_questions(app: &mut App, source: SocketAddr, secs: u64) {
    let at = Instant::now()
        .checked_sub(Duration::from_secs(secs))
        .unwrap_or_else(Instant::now);
    for rows in app
        .services
        .iter_mut()
        .map(|s| &mut s.questions)
        .chain(app.pending_instances.iter_mut().map(|p| &mut p.questions))
        .chain(app.enum_entries.iter_mut().map(|e| &mut e.questions))
    {
        for q in rows.iter_mut().filter(|q| q.2 == source) {
            q.3 = at;
        }
    }
}

fn dumped_sources(app: &App) -> Vec<String> {
    app.state_dump().services[0]
        .questions
        .iter()
        .map(|q| q.source.clone())
        .collect()
}

const PAST_WINDOW: u64 = QUESTION_WINDOW.as_secs() + 60;
