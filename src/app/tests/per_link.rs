// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #441: discovery is dampened per ingress link ---

use super::*;

const INSTANCE: &str = "test._http._tcp.local";

/// Pin the usable links to `names` (both families, IPv6 index 2, 3, …),
/// so tests don't depend on this host's interfaces.
fn pin_links(app: &mut App, names: &[&str]) {
    app.link_stats = browse::LinkStats {
        v4: names
            .iter()
            .map(|n| (n.to_string(), std::net::Ipv4Addr::new(192, 168, 1, 2)))
            .collect(),
        v6: names
            .iter()
            .enumerate()
            .map(|(i, n)| (n.to_string(), i as u32 + 2))
            .collect(),
        ..Default::default()
    };
}

/// A pending instance (PTR seen) on two links, its SRV/TXT streams
/// started, and its queries captured.
fn two_link_app() -> (App, mpsc::Receiver<browse::QueryBatch>) {
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0", "wlan0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    (app, rx)
}

/// `srv_record` received on `iface` (index `ifindex`), without the
/// interface name when `iface` is empty.
fn srv_on(iface: &str, ifindex: u32) -> browse::RawRecord {
    let mut srv = srv_record(120);
    srv.iface = iface.to_string();
    srv.ifindex = ifindex;
    srv
}

fn interval(app: &App, rtype: u16) -> Duration {
    app.scheduler.continuous()[&(INSTANCE.to_string(), rtype)].interval
}

/// Make every live (not dampened) stream due now.
fn all_due(app: &mut App) {
    let now = Instant::now() - Duration::from_millis(1);
    for entry in app.scheduler.continuous_mut().values_mut() {
        if entry.interval < MAX_CONTINUOUS_INTERVAL {
            entry.next_due = now;
        }
    }
}

/// The links each question of the last batch goes out on, by type.
fn links_of(rx: &mpsc::Receiver<browse::QueryBatch>, rtype: u16) -> Option<Vec<String>> {
    rx.try_iter()
        .last()?
        .into_iter()
        .find(|q| u16::from(q.record_type) == rtype && q.name.eq_ignore_ascii_case(INSTANCE))
        .map(|q| q.links)
}

#[test]
fn a_unique_answer_on_one_link_dampens_that_link_only() {
    let (mut app, rx) = two_link_app();
    ingest(&mut app, &srv_on("eth0", 2));
    assert!(
        interval(&app, 33) < MAX_CONTINUOUS_INTERVAL,
        "wlan0 still asks"
    );
    rx.try_iter().count();
    all_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
}

#[test]
fn answers_on_every_link_dampen_the_stream() {
    let (mut app, _rx) = two_link_app();
    ingest(&mut app, &srv_on("eth0", 2));
    ingest(&mut app, &srv_on("wlan0", 3));
    assert_eq!(interval(&app, 33), MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn an_answer_on_a_link_without_a_resolved_name_covers_it_by_index() {
    // IP_PKTINFO always gives the index; an unresolved name still maps to
    // its link through the IPv6 index.
    let (mut app, rx) = two_link_app();
    ingest(&mut app, &srv_on("", 3));
    rx.try_iter().count();
    all_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["eth0".to_string()]));
}

#[test]
fn a_single_link_app_dampens_as_before() {
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    ingest(&mut app, &srv_on("eth0", 2));
    assert_eq!(interval(&app, 33), MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn an_answer_cached_on_one_link_starts_the_stream_on_the_others() {
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0", "wlan0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_on("eth0", 2));
    app.send_queries(); // the SRV stream is created now
    assert!(interval(&app, 33) < MAX_CONTINUOUS_INTERVAL);
    all_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
}

#[test]
fn a_link_appearing_later_restarts_a_dampened_stream_there() {
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    ingest(&mut app, &srv_on("eth0", 2));
    assert_eq!(interval(&app, 33), MAX_CONTINUOUS_INTERVAL);
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    assert_eq!(
        interval(&app, 33),
        Duration::from_secs(1),
        "startup schedule"
    );
    rx.try_iter().count();
    all_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
}

#[test]
fn a_query_overheard_on_one_link_stands_in_for_ours_there_only() {
    // RFC 6762 §7.3 per link: another querier asked on eth0, so ours goes
    // out on wlan0 alone and still counts as sent.
    let (mut app, rx) = two_link_app();
    let mut ev = query_event(
        "Test._http._tcp.local.",
        33,
        "SRV",
        false,
        Vec::new(),
        remote_source(),
    );
    ev.questions[0].iface = "eth0".to_string();
    ev.questions[0].ifindex = 2;
    app.ingest_event(&ev);
    rx.try_iter().count();
    let suppressed = app.diagnostics.suppressed_continuous;
    all_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
    assert_eq!(app.diagnostics.suppressed_continuous, suppressed);
}

#[test]
fn per_link_sends_keep_one_self_row_per_question() {
    let (mut app, _rx) = two_link_app();
    ingest(&mut app, &srv_on("eth0", 2));
    all_due(&mut app);
    app.send_queries();
    let rows = app
        .pending_instances
        .iter()
        .flat_map(|p| p.questions.iter())
        .filter(|q| q.1 == "SRV" && q.2 == SELF_SOURCE)
        .count()
        + app
            .services
            .iter()
            .flat_map(|s| s.questions.iter())
            .filter(|q| q.1 == "SRV" && q.2 == SELF_SOURCE)
            .count();
    assert_eq!(rows, 1);
}

#[test]
fn a_question_queued_for_two_link_sets_asks_their_union() {
    let mut app = App::new().unwrap();
    let ptr = |links: &[&str]| browse::QueryRequest {
        name: "_http._tcp.local".to_string(),
        record_type: TYPE::PTR,
        known_answers: Vec::new(),
        qu: false,
        links: links.iter().map(|l| l.to_string()).collect(),
    };
    app.queue_question(ptr(&["eth0"]));
    app.queue_question(ptr(&["wlan0", "eth0"]));
    assert_eq!(app.outbox.len(), 1);
    assert_eq!(app.outbox[0].links, ["eth0", "wlan0"]);
    // One copy for every link wins.
    app.queue_question(ptr(&[]));
    assert!(app.outbox[0].links.is_empty());
}

#[test]
fn an_overheard_query_skips_its_link_among_the_uncovered_ones() {
    // Three links: eth0 answered, the query overheard on wlan0, so ours
    // goes out on usb0 alone.
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0", "usb0", "wlan0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    ingest(&mut app, &srv_on("eth0", 2));
    let mut ev = query_event(
        "Test._http._tcp.local.",
        33,
        "SRV",
        false,
        Vec::new(),
        remote_source(),
    );
    ev.questions[0].iface = "wlan0".to_string();
    ev.questions[0].ifindex = 4;
    app.ingest_event(&ev);
    rx.try_iter().count();
    all_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["usb0".to_string()]));
}

#[test]
fn an_interface_selection_limits_the_links_to_cover() {
    // With `-i eth0`, wlan0 isn't asked at all: one answer on eth0 covers
    // every usable link and dampens the stream.
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.interfaces = Some(HashSet::from(["eth0".to_string()]));
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    ingest(&mut app, &srv_on("eth0", 2));
    assert_eq!(interval(&app, 33), MAX_CONTINUOUS_INTERVAL);
}
