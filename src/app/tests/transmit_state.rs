// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- Transmit state (#253) ---

use super::*;

#[test]
fn queries_hold_while_no_family_can_transmit() {
    let mut app = App::new().unwrap();
    let key = due_http_stream(&mut app);
    app.query_tx.transmit().pin(false, false);
    let sent_before = app.diagnostics.q_sent_continuous;
    app.send_queries();
    assert_eq!(
        app.diagnostics.q_sent_continuous, sent_before,
        "nothing counted"
    );
    let entry = app
        .scheduler
        .continuous()
        .get(&key)
        .expect("still scheduled");
    assert_eq!(entry.interval, Duration::from_secs(1), "no backoff");
    assert!(
        app.scheduler
            .query_history()
            .get(&Scheduler::provenance_key(&key.0, key.1))
            .is_none_or(|s| s.transmitted.is_none()),
        "no phantom transmission"
    );
}

#[test]
fn one_family_transmitting_keeps_queries_going() {
    let mut app = App::new().unwrap();
    let key = due_http_stream(&mut app);
    app.query_tx.transmit().pin(false, true);
    let sent_before = app.diagnostics.q_sent_continuous;
    app.send_queries();
    assert!(app.diagnostics.q_sent_continuous > sent_before);
    assert_eq!(
        app.scheduler
            .continuous()
            .get(&key)
            .expect("scheduled")
            .interval,
        Duration::from_secs(2),
        "backoff advances as usual"
    );
    assert!(app
        .scheduler
        .query_history()
        .get(&Scheduler::provenance_key(&key.0, key.1))
        .is_some_and(|s| s.transmitted.is_some()));
}

#[test]
fn refresh_attempts_are_kept_while_held() {
    let mut app = app_with_stale_enum_row();
    app.query_tx.transmit().pin(false, false);
    for _ in 0..8 {
        app.send_queries();
        make_refresh_due(&mut app, "_services._dns-sd._udp.local", 12);
    }
    assert_eq!(
        app.diagnostics.q_sent_refresh, 0,
        "no attempt used while held"
    );
    app.query_tx.transmit().pin(true, true);
    app.send_queries();
    assert_eq!(
        app.diagnostics.q_sent_refresh, 1,
        "refresh goes out on resume"
    );
}

#[test]
fn held_records_still_expire_at_ttl() {
    // Holding keeps refresh attempts, not freshness: a record whose
    // TTL runs out during the outage expires as usual.
    let mut app = app_with_stale_enum_row();
    app.query_tx.transmit().pin(false, false);
    app.enum_entries[0].answers[1].received_at = Instant::now() - Duration::from_secs(4600);
    app.send_queries();
    assert_eq!(app.diagnostics.q_sent_refresh, 0);
    assert_eq!(
        record_liveness(&app.enum_entries[0].answers[1]),
        RecordLiveness::Expired
    );
}

#[test]
fn resume_restarts_discovery_with_the_startup_schedule() {
    let mut app = App::new().unwrap();
    let key = due_http_stream(&mut app);
    // Backed off far, as after a long outage.
    if let Some(entry) = app.scheduler.continuous_mut().get_mut(&key) {
        entry.interval = Duration::from_secs(3600);
        entry.next_due = Instant::now() + Duration::from_secs(3600);
    }
    app.query_tx.transmit().pin(false, false);
    app.send_queries();
    app.query_tx.transmit().pin(true, false);
    app.send_queries();
    let entry = app.scheduler.continuous().get(&key).expect("re-created");
    assert_eq!(entry.interval, Duration::from_secs(1), "startup interval");
    assert!(
        entry.next_due <= Instant::now() + Duration::from_millis(120),
        "first query within the 20–120 ms startup window"
    );
}

#[test]
fn transmit_state_shows_in_diagnostics_and_dump() {
    let app = App::new().unwrap();
    app.query_tx.transmit().pin(false, true);
    assert!(app
        .diagnostics_rows()
        .iter()
        .any(|(k, v)| k == "transmit" && v == "v4 paused · v6 ok"));
    let dump = app.state_dump();
    assert_eq!(dump.diagnostics["transmit_v4"], 0);
    assert_eq!(dump.diagnostics["transmit_v6"], 1);
}

#[test]
fn hold_drops_expired_refresh_summaries_and_keeps_live_attempts() {
    let mut app = app_with_stale_enum_row();
    let key = ("_services._dns-sd._udp.local".to_string(), 12);
    app.requery_expiring();
    assert!(
        app.scheduler.requeries().contains_key(&key),
        "refresh scheduled"
    );
    let attempts = |app: &App| {
        app.scheduler
            .refresh_rows()
            .values()
            .map(|s| s.attempts)
            .sum::<u8>()
    };
    assert_eq!(attempts(&app), 1);
    // Held: the live row keeps its attempt; nothing is sent.
    app.query_tx.transmit().pin(false, false);
    make_refresh_due(&mut app, "_services._dns-sd._udp.local", 12);
    app.send_queries();
    assert_eq!(attempts(&app), 1, "no attempt used while held");
    assert_eq!(app.diagnostics.q_sent_refresh, 1);
    // The record expires during the hold: its summary goes too.
    app.enum_entries[0].answers[1].received_at = Instant::now() - Duration::from_secs(4600);
    app.send_queries();
    assert!(
        !app.scheduler.requeries().contains_key(&key),
        "no refresh shown for it"
    );
    assert!(app.scheduler.refresh_rows().is_empty());
    assert_eq!(app.requery_overdue(), 0);
}

#[test]
fn resume_refreshes_the_link_snapshot_before_queries() {
    let mut app = App::new().unwrap();
    due_http_stream(&mut app);
    app.query_tx.transmit().pin(false, false);
    // Well inside the 10 s snapshot interval: no routine refresh.
    let stale = Instant::now() - Duration::from_secs(5);
    app.last_ip_refresh = stale;
    app.send_queries();
    assert_eq!(app.last_ip_refresh, stale, "held ticks leave it alone");
    app.query_tx.transmit().pin(true, false);
    app.send_queries();
    assert!(
        app.last_ip_refresh > stale,
        "snapshot refreshed on resume, before resumed queries record interfaces"
    );
}

fn due_http_stream(app: &mut App) -> (String, u16) {
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
    key
}
