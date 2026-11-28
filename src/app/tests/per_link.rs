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

/// A remote query for the instance's SRV, overheard on `iface`.
fn overhear_srv(app: &mut App, iface: &str, ifindex: u32) {
    let mut ev = query_event(
        "Test._http._tcp.local.",
        33,
        "SRV",
        false,
        Vec::new(),
        remote_source(),
    );
    ev.questions[0].iface = iface.to_string();
    ev.questions[0].ifindex = ifindex;
    app.ingest_event(&ev);
}

#[test]
fn a_query_overheard_on_a_covered_link_leaves_ours_in_place() {
    // eth0 answered, so we ask wlan0 alone; a query overheard on eth0
    // can't stand in for ours on wlan0, and isn't used up.
    let (mut app, rx) = two_link_app();
    ingest(&mut app, &srv_on("eth0", 2));
    overhear_srv(&mut app, "eth0", 2);
    rx.try_iter().count();
    let suppressed = app.diagnostics.suppressed_continuous;
    all_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
    assert_eq!(app.diagnostics.suppressed_continuous, suppressed);
    assert!(app
        .scheduler
        .overheard()
        .contains_key(&(INSTANCE.to_string(), 33)));
}

#[test]
fn a_refresh_overheard_on_one_link_still_goes_out_on_the_others() {
    // §7.3 per link for the cache refresh too: the query overheard on
    // eth0 stands in there; wlan0 gets its refresh, which counts as sent.
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0", "wlan0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 33 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    overhear_srv(&mut app, "eth0", 2);
    let (sent, suppressed) = (
        app.diagnostics.q_sent_refresh,
        app.diagnostics.suppressed_refresh,
    );
    app.requery_expiring();
    app.flush_outbox();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
    assert_eq!(app.diagnostics.q_sent_refresh, sent + 1);
    assert_eq!(app.diagnostics.suppressed_refresh, suppressed);
}

#[test]
fn capped_backoff_on_an_unanswered_link_is_kept() {
    // eth0 answered, wlan0 not: the stream backs off to the hourly cap
    // normally, and nothing restarts it while the links stay the same.
    let (mut app, _rx) = two_link_app();
    ingest(&mut app, &srv_on("eth0", 2));
    let later = Instant::now() + MAX_CONTINUOUS_INTERVAL;
    let entry = app
        .scheduler
        .continuous_mut()
        .get_mut(&(INSTANCE.to_string(), 33))
        .unwrap();
    entry.interval = MAX_CONTINUOUS_INTERVAL;
    entry.next_due = later;
    app.send_queries();
    assert_eq!(interval(&app, 33), MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn a_scoped_query_records_only_its_links() {
    let (mut app, _rx) = two_link_app();
    ingest(&mut app, &srv_on("eth0", 2));
    all_due(&mut app);
    app.send_queries();
    let state = app
        .scheduler
        .history(&Scheduler::provenance_key(INSTANCE, 33))
        .expect("sent");
    assert_eq!(state.transmitted_interfaces, "wlan0");
}

/// Make every link stream due now.
fn link_streams_due(app: &mut App) {
    let now = Instant::now() - Duration::from_millis(1);
    for stream in app.scheduler.link_streams_mut().values_mut() {
        stream.next_due = now;
    }
}

/// The interval of `rtype`'s link stream on `link`, if one runs.
fn link_stream(app: &mut App, name: &str, rtype: u16, link: &str) -> Option<Duration> {
    app.scheduler
        .link_streams_mut()
        .get(&((name.to_string(), rtype), link.to_string()))
        .map(|s| s.interval)
}

/// Park `name`/`rtype`'s stream at the hourly cap, as backoff or
/// dampening leaves it.
fn park(app: &mut App, name: &str, rtype: u16) {
    let entry = app
        .scheduler
        .continuous_mut()
        .get_mut(&(name.to_string(), rtype))
        .unwrap();
    entry.interval = MAX_CONTINUOUS_INTERVAL;
    entry.next_due = Instant::now() + MAX_CONTINUOUS_INTERVAL;
}

#[test]
fn a_link_appearing_later_is_asked_alone_on_a_dampened_stream() {
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
        MAX_CONTINUOUS_INTERVAL,
        "eth0 keeps its schedule"
    );
    assert_eq!(
        link_stream(&mut app, INSTANCE, 33, "wlan0"),
        Some(Duration::from_secs(1))
    );
    rx.try_iter().count();
    link_streams_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
}

#[test]
fn a_reconnecting_link_never_restarts_browsing_on_the_others() {
    // A PTR browse covers no link: when wlan0 (re)connects, it starts over
    // on wlan0 alone, and eth0 keeps its backed-off schedule.
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    let browse = "_http._tcp.local";
    park(&mut app, browse, 12);
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    assert_eq!(
        app.scheduler.continuous()[&(browse.to_string(), 12)].interval,
        MAX_CONTINUOUS_INTERVAL
    );
    rx.try_iter().count();
    link_streams_due(&mut app);
    app.send_queries();
    let asked: Vec<_> = rx
        .try_iter()
        .flatten()
        .filter(|q| q.name == browse)
        .map(|q| q.links)
        .collect();
    assert_eq!(asked, [vec!["wlan0".to_string()]], "eth0 not asked");
}

#[test]
fn a_link_that_comes_back_is_asked_again_alone() {
    // Both links answered (dampened); wlan0 goes away and returns: its old
    // answer no longer counts, so wlan0 alone is asked again.
    let (mut app, rx) = two_link_app();
    ingest(&mut app, &srv_on("eth0", 2));
    ingest(&mut app, &srv_on("wlan0", 3));
    assert_eq!(interval(&app, 33), MAX_CONTINUOUS_INTERVAL);
    pin_links(&mut app, &["eth0"]);
    app.send_queries();
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    assert_eq!(interval(&app, 33), MAX_CONTINUOUS_INTERVAL);
    rx.try_iter().count();
    link_streams_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
}

#[test]
fn a_link_stream_starts_at_the_startup_delay() {
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    let _rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    pin_links(&mut app, &["eth0", "wlan0"]);
    let before = Instant::now();
    app.send_queries();
    let next = app.scheduler.link_streams_mut()[&((INSTANCE.to_string(), 33), "wlan0".to_string())]
        .next_due;
    assert!(next <= before + Duration::from_millis(200), "startup delay");
}

#[test]
fn a_new_link_leaves_the_other_links_schedule_alone() {
    let (mut app, _rx) = two_link_app();
    all_due(&mut app);
    app.send_queries();
    let key = (INSTANCE.to_string(), 33);
    let (due, step) = {
        let e = &app.scheduler.continuous()[&key];
        (e.next_due, e.interval)
    };
    pin_links(&mut app, &["eth0", "usb0", "wlan0"]);
    app.send_queries();
    let e = &app.scheduler.continuous()[&key];
    assert_eq!((e.next_due, e.interval), (due, step));
}

#[test]
fn an_answer_on_an_unknown_link_still_lets_a_new_link_be_asked() {
    // Its link unknown, the answer dampens at once and covers the links
    // usable then; a link appearing later is uncovered and asked alone.
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    ingest(&mut app, &srv_on("", 0));
    assert_eq!(interval(&app, 33), MAX_CONTINUOUS_INTERVAL);
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    rx.try_iter().count();
    link_streams_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["wlan0".to_string()]));
}

#[test]
fn a_link_stream_joins_the_stream_once_caught_up() {
    // The question's stream is at 4 s: the new link's stream asks at 1 s
    // and 2 s, then joins, and the question goes out on every link again.
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    let browse = "_http._tcp.local";
    let entry = app
        .scheduler
        .continuous_mut()
        .get_mut(&(browse.to_string(), 12))
        .unwrap();
    entry.interval = Duration::from_secs(4);
    entry.next_due = Instant::now() + MAX_CONTINUOUS_INTERVAL;
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    for _ in 0..2 {
        link_streams_due(&mut app);
        app.send_queries();
    }
    assert_eq!(link_stream(&mut app, browse, 12, "wlan0"), None, "joined");
    rx.try_iter().count();
    let entry = app
        .scheduler
        .continuous_mut()
        .get_mut(&(browse.to_string(), 12))
        .unwrap();
    entry.next_due = Instant::now() - Duration::from_millis(1);
    app.send_queries();
    let asked: Vec<_> = rx
        .try_iter()
        .flatten()
        .filter(|q| q.name == browse)
        .map(|q| q.links)
        .collect();
    assert_eq!(asked, [Vec::<String>::new()], "every link");
}

#[test]
fn an_answer_on_the_new_link_ends_its_stream() {
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    let _rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    assert!(link_stream(&mut app, INSTANCE, 33, "wlan0").is_some());
    ingest(&mut app, &srv_on("wlan0", 3));
    assert_eq!(link_stream(&mut app, INSTANCE, 33, "wlan0"), None);
}

#[test]
fn a_query_overheard_on_the_new_link_stands_in_for_its_stream_send() {
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    park(&mut app, INSTANCE, 33);
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    overhear_srv(&mut app, "wlan0", 3);
    rx.try_iter().count();
    let suppressed = app.diagnostics.suppressed_continuous;
    link_streams_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), None, "no SRV sent");
    assert_eq!(app.diagnostics.suppressed_continuous, suppressed + 1);
    assert_eq!(
        link_stream(&mut app, INSTANCE, 33, "wlan0"),
        Some(Duration::from_secs(2)),
        "the stream still doubles"
    );
}

#[test]
fn the_question_s_stream_skips_a_link_on_its_own_stream() {
    // wlan0 just came up and runs its own startup stream: when the
    // question's stream comes due meanwhile, it asks eth0 only.
    let mut app = App::new().unwrap();
    pin_links(&mut app, &["eth0"]);
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    for stream in app.scheduler.link_streams_mut().values_mut() {
        stream.next_due = Instant::now() + MAX_CONTINUOUS_INTERVAL;
    }
    rx.try_iter().count();
    all_due(&mut app);
    app.send_queries();
    assert_eq!(links_of(&rx, 33), Some(vec!["eth0".to_string()]));
}

#[test]
fn with_every_link_covered_or_streaming_the_question_s_stream_only_advances() {
    // eth0 answered, wlan0 on its own stream: the question's stream has
    // no link left this round, so it sends nothing and moves on.
    let (mut app, rx) = two_link_app();
    ingest(&mut app, &srv_on("eth0", 2));
    pin_links(&mut app, &["eth0"]);
    app.send_queries();
    pin_links(&mut app, &["eth0", "wlan0"]);
    app.send_queries();
    for stream in app.scheduler.link_streams_mut().values_mut() {
        stream.next_due = Instant::now() + MAX_CONTINUOUS_INTERVAL;
    }
    rx.try_iter().count();
    all_due(&mut app);
    let before = app.scheduler.continuous()[&(INSTANCE.to_string(), 33)].interval;
    app.send_queries();
    assert_eq!(links_of(&rx, 33), None, "no SRV this round");
    assert!(app.scheduler.continuous()[&(INSTANCE.to_string(), 33)].interval > before);
}
