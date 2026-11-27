// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #431: our own sent query copies feed the multicast-rate check ---

use super::*;

/// Our query copy for `name` SRV on `iface`, sent at `at`.
fn own(at: Instant, name: &str, iface: &str) -> browse::OwnSend {
    browse::OwnSend {
        questions: vec![(name.to_string(), 33)],
        iface: iface.to_string(),
        ifindex: 2,
        v6: false,
        sent_at: at,
    }
}

/// Hand the app `events` and our own sends `sent` through its channels,
/// as the listener does, and drain them in one tick.
fn deliver(app: &mut App, events: Vec<browse::Event>, sent: Vec<browse::OwnSend>) {
    let (tx, rx) = mpsc::channel();
    let (own_tx, own_rx) = mpsc::channel();
    app.rx = rx;
    app.own_rx = own_rx;
    for ev in events {
        tx.send(ev).unwrap();
    }
    for s in sent {
        own_tx.send(s).unwrap();
    }
    app.drain_events();
}

/// The SRV row's copy on `eth0`, received at `at`.
fn srv_copy(at: Instant) -> browse::Event {
    let mut rec = srv_record(120);
    rec.iface = "eth0".to_string();
    rec.ifindex = 2;
    rec.received_at = at;
    let mut ev = event_for(&rec);
    ev.received_at = at;
    ev
}

#[test]
fn a_repeat_after_our_query_names_mex_on_the_answers_row() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    let base = Instant::now() - Duration::from_secs(2);
    let ms = |n| base + Duration::from_millis(n);
    deliver(
        &mut app,
        vec![srv_copy(ms(20)), srv_copy(ms(270))],
        vec![
            own(ms(0), "Test._http._tcp.local", "eth0"),
            own(ms(250), "Test._http._tcp.local", "eth0"),
        ],
    );
    let flood: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.kind == anomalies::AnomalyKind::MulticastRateLimit)
        .map(|a| a.message)
        .collect();
    let expected = "multicast 2 times in 0.25 s, as little as 0.25 s apart, 2 of 2 after \
                    mex's own queries, answering mex (this host) asking \
                    Test._http._tcp.local. SRV";
    assert_eq!(flood, [expected]);
    // The state dump carries the same text.
    let dumped: Vec<_> = app
        .state_dump()
        .anomalies
        .into_iter()
        .filter(|a| a.kind == "multicast-rate-limit")
        .map(|a| a.message)
        .collect();
    assert_eq!(dumped, [expected]);
}

#[test]
fn a_passive_browser_records_no_own_sends() {
    // #431: passive mode sends nothing, so nothing names mex.
    let mut app = App::new_with(true, None).unwrap();
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    app.poll_continuous();
    // Give the listener time to report anything it might have sent.
    std::thread::sleep(Duration::from_millis(100));
    app.drain_events();
    assert!(app.own_sends.is_empty());
}

#[test]
fn own_sends_touch_no_view_or_counter() {
    let mut app = App::new().unwrap();
    let packets = app.packet_count;
    let sent = (0..3)
        .map(|_| own(Instant::now(), "_http._tcp.local", "eth0"))
        .collect();
    deliver(&mut app, Vec::new(), sent);
    assert_eq!(app.own_sends.len(), 3, "retained for the rate check");
    assert_eq!(app.packet_count, packets);
    assert!(app.raw_events.is_empty());
    assert!(app.diagnostics.packet_times.is_empty());
    assert_eq!(app.diagnostics.questions_total, 0);
    assert!(app.sightings.is_empty());
    assert!(app.scheduler.overheard().is_empty());
    assert!(app.enum_entries.iter().all(|e| e.questions.is_empty()));
}

#[test]
fn own_sends_older_than_the_retained_window_are_pruned() {
    let mut app = App::new().unwrap();
    let base = Instant::now() - Duration::from_secs(10);
    let ms = |n| base + Duration::from_millis(n);
    // The oldest retained packet arrives at 5 s: a copy then can answer
    // our sends from 4 s on, not earlier.
    deliver(
        &mut app,
        vec![srv_copy(ms(5000))],
        vec![
            own(ms(3000), "a.local", "eth0"),
            own(ms(4000), "b.local", "eth0"),
            own(ms(4500), "c.local", "eth0"),
        ],
    );
    let kept: Vec<_> = app
        .own_sends
        .iter()
        .map(|s| s.questions[0].0.as_str())
        .collect();
    assert_eq!(kept, ["b.local", "c.local"]);
}

#[test]
fn own_sends_wait_for_a_reply_while_nothing_is_retained() {
    let mut app = App::new().unwrap();
    let long_ago = Instant::now() - Duration::from_secs(60);
    deliver(&mut app, Vec::new(), vec![own(long_ago, "a.local", "eth0")]);
    assert_eq!(app.own_sends.len(), 1, "only the cap applies");
}

#[test]
fn own_sends_are_capped() {
    let mut app = App::new().unwrap();
    let now = Instant::now();
    let sent = (0..OWN_SENDS_CAP + 5)
        .map(|i| own(now, &format!("n{i}.local"), "eth0"))
        .collect();
    deliver(&mut app, Vec::new(), sent);
    assert_eq!(app.own_sends.len(), OWN_SENDS_CAP);
    assert_eq!(
        app.own_sends[0].questions[0].0, "n5.local",
        "oldest dropped"
    );
}
