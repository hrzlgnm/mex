// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! #429: questions for names nothing here owns still get rate findings.

use super::*;

/// A querier asking `name`/`rtype` `n` times, `gap` apart and ending now,
/// on eth0, from `source`.
fn storm(
    app: &mut App,
    name: &str,
    rtype: u16,
    rtype_str: &str,
    n: u32,
    gap: Duration,
    source: SocketAddr,
) {
    let now = Instant::now();
    for i in 0..n {
        let at = now - gap * (n - 1 - i);
        let mut ev = query_event(name, rtype, rtype_str, false, Vec::new(), source);
        ev.received_at = at;
        ev.questions[0].received_at = at;
        ev.questions[0].iface = "eth0".to_string();
        ev.questions[0].ifindex = 2;
        ingest_packet(app, ev);
    }
}

fn storm_at(app: &mut App, name: &str, n: u32, gap: Duration) {
    storm(app, name, 28, "AAAA", n, gap, chatty());
}

fn chatty() -> SocketAddr {
    "192.168.1.70:5353".parse().unwrap()
}

fn rate(app: &App) -> Vec<anomalies::Anomaly> {
    findings_of(app, anomalies::AnomalyKind::QueryRateLimit)
}

#[test]
fn an_unowned_question_storm_is_flagged_unattributed() {
    let mut app = App::new().unwrap();
    storm_at(&mut app, "echo-dot.local.", 4, Duration::from_millis(200));
    let found = rate(&app);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].service, anomalies::UNATTRIBUTED_SERVICE);
    assert_eq!(found[0].source.as_deref(), Some("192.168.1.70:5353@eth0"));
    assert!(
        found[0].message.contains("asked 4 times"),
        "{}",
        found[0].message
    );
}

#[test]
fn an_unowned_question_a_second_apart_is_fine() {
    let mut app = App::new().unwrap();
    storm_at(&mut app, "echo-dot.local.", 4, Duration::from_secs(1));
    assert!(rate(&app).is_empty());
}

#[test]
fn an_unowned_storm_from_an_ephemeral_port_is_out_of_scope() {
    // §5.1 one-shot queriers aren't bound by §5.2's pacing.
    let mut app = App::new().unwrap();
    let one_shot: SocketAddr = "192.168.1.70:40000".parse().unwrap();
    storm(
        &mut app,
        "echo-dot.local.",
        28,
        "AAAA",
        4,
        Duration::from_millis(200),
        one_shot,
    );
    assert!(rate(&app).is_empty());
}

#[test]
fn a_service_naming_the_host_later_claims_the_storm() {
    let mut app = App::new().unwrap();
    storm_at(&mut app, "test.local.", 4, Duration::from_millis(200));
    assert_eq!(rate(&app)[0].service, anomalies::UNATTRIBUTED_SERVICE);
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    let found = rate(&app);
    assert!(!found.is_empty());
    assert!(
        found.iter().all(|a| a.service == "test.local"),
        "{found:#?}"
    );
}

#[test]
fn names_fold_ascii_only() {
    // RFC 6762 §16: `ECHO` and `echo` are one name, `É` and `é` two.
    let mut app = App::new().unwrap();
    let now = Instant::now();
    for (i, name) in ["echo.local.", "ECHO.local.", "Echo.local."]
        .iter()
        .enumerate()
    {
        let mut ev = query_event(name, 28, "AAAA", false, Vec::new(), chatty());
        ev.received_at = now - Duration::from_millis(200 * (2 - i as u64));
        ev.questions[0].received_at = ev.received_at;
        ev.questions[0].iface = "eth0".to_string();
        ev.questions[0].ifindex = 2;
        ingest_packet(&mut app, ev);
    }
    assert_eq!(rate(&app).len(), 1, "one question: {:#?}", rate(&app));

    let mut app = App::new().unwrap();
    for (i, name) in ["\u{c9}cho.local.", "\u{e9}cho.local."].iter().enumerate() {
        let mut ev = query_event(name, 28, "AAAA", false, Vec::new(), chatty());
        ev.received_at = now - Duration::from_millis(200 * (1 - i as u64));
        ev.questions[0].received_at = ev.received_at;
        ev.questions[0].iface = "eth0".to_string();
        ev.questions[0].ifindex = 2;
        ingest_packet(&mut app, ev);
    }
    assert!(rate(&app).is_empty(), "two questions: {:#?}", rate(&app));
}

#[test]
fn one_asking_on_each_of_two_links_is_no_repeat() {
    let mut app = App::new().unwrap();
    let now = Instant::now();
    for (i, (iface, ifindex)) in [("eth0", 2), ("wlan0", 3)].into_iter().enumerate() {
        let mut ev = query_event("echo-dot.local.", 28, "AAAA", false, Vec::new(), chatty());
        ev.received_at = now - Duration::from_millis(100 * (1 - i as u64));
        ev.questions[0].received_at = ev.received_at;
        ev.questions[0].iface = iface.to_string();
        ev.questions[0].ifindex = ifindex;
        ingest_packet(&mut app, ev);
    }
    assert!(rate(&app).is_empty(), "{:#?}", rate(&app));
}

#[test]
fn a_long_storm_is_one_sighting_and_no_questions_row() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    let before = app.sightings.len();
    storm_at(&mut app, "echo-dot.local.", 2000, Duration::from_millis(1));
    assert_eq!(app.sightings.len(), before + 1, "one sighting");
    assert_eq!(rate(&app).len(), 1, "one finding");
    assert!(
        app.services.iter().all(|s| s.questions.is_empty()),
        "no Questions row"
    );
}

#[test]
fn owned_questions_keep_their_rows_and_findings() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    let before = app.sightings.len();
    storm_at(&mut app, "test.local.", 4, Duration::from_millis(200));
    assert_eq!(app.sightings.len(), before, "owned: no sighting");
    let found = rate(&app);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(
        found[0].service, "Test._http._tcp.local",
        "on its row, as before"
    );
    assert!(
        !app.services[0].questions.is_empty(),
        "the Questions row stays"
    );
}
