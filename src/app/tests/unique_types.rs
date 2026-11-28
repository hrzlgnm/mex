// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #438: SRV/TXT/A/AAAA are unique by type, flush bit or not ---

use super::*;

/// The `(name, type)` of every question handed over so far.
fn asked(rx: &mpsc::Receiver<browse::QueryBatch>) -> Vec<(String, u16)> {
    rx.try_iter()
        .flatten()
        .map(|q| (q.name.to_ascii_lowercase(), u16::from(q.record_type)))
        .collect()
}

fn stream_interval(app: &App, name: &str, rtype: u16) -> Duration {
    app.scheduler
        .continuous()
        .get(&(name.to_string(), rtype))
        .unwrap_or_else(|| panic!("{name} {rtype} stream"))
        .interval
}

/// A pending instance (PTR seen) with its SRV/TXT streams started.
fn pending_app() -> App {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    app
}

const INSTANCE: &str = "test._http._tcp.local";

#[test]
fn srv_and_txt_without_the_flush_bit_dampen_their_streams() {
    let mut app = pending_app();
    let mut srv = srv_record(120);
    srv.flush_bit = false;
    ingest(&mut app, &srv);
    let mut txt = txt_record("a=1");
    txt.flush_bit = false;
    ingest(&mut app, &txt);
    assert_eq!(stream_interval(&app, INSTANCE, 33), MAX_CONTINUOUS_INTERVAL);
    assert_eq!(stream_interval(&app, INSTANCE, 16), MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn a_ptr_answer_keeps_its_discovery_stream() {
    // PTR is shared (RFC 6762 §7.1): more instances may answer, so its
    // stream keeps doubling and lists known answers instead.
    let app = pending_app();
    assert!(stream_interval(&app, "_http._tcp.local", 12) < MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn a_goodbye_never_dampens() {
    let mut app = pending_app();
    let mut bye = srv_record(0);
    bye.flush_bit = false;
    ingest(&mut app, &bye);
    assert!(stream_interval(&app, INSTANCE, 33) < MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn a_txt_arriving_before_its_srv_dampens_its_stream() {
    // The TXT waits on the pending instance for the SRV, but it already
    // answers the TXT question that instance drives.
    let mut app = pending_app();
    let mut txt = txt_record("a=1");
    txt.flush_bit = false;
    ingest(&mut app, &txt);
    assert!(app.services.is_empty(), "still pending");
    assert_eq!(stream_interval(&app, INSTANCE, 16), MAX_CONTINUOUS_INTERVAL);
    assert!(stream_interval(&app, INSTANCE, 33) < MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn srv_and_txt_cached_before_their_streams_start_dampened() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    let mut srv = srv_record(120);
    srv.flush_bit = false;
    ingest(&mut app, &srv);
    let mut txt = txt_record("a=1");
    txt.flush_bit = false;
    ingest(&mut app, &txt);
    app.send_queries(); // the streams are created now
    assert_eq!(stream_interval(&app, INSTANCE, 33), MAX_CONTINUOUS_INTERVAL);
    assert_eq!(stream_interval(&app, INSTANCE, 16), MAX_CONTINUOUS_INTERVAL);
}

#[test]
fn a_dampened_question_comes_back_only_through_the_refresh() {
    let mut app = pending_app();
    let rx = capture(&mut app);
    let mut srv = srv_record(120);
    srv.flush_bit = false;
    ingest(&mut app, &srv);
    // Every stream due: the dampened SRV is not among them.
    let now = Instant::now() - Duration::from_millis(1);
    for entry in app.scheduler.continuous_mut().values_mut() {
        if entry.interval < MAX_CONTINUOUS_INTERVAL {
            entry.next_due = now;
        }
    }
    app.send_queries();
    let srv_key = (INSTANCE.to_string(), 33);
    assert!(!asked(&rx).contains(&srv_key));
    // Aged into its 80% window, the refresh asks it.
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 33 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    app.send_queries();
    assert!(asked(&rx).contains(&srv_key));
}

#[test]
fn a_txt_that_expired_while_pending_does_not_dampen_on_promotion() {
    // A TTL-1 TXT that waited past its TTL for the SRV is no answer any
    // more: dampening on promotion would leave the question unasked for
    // an hour, since the refresh skips an expired row.
    let mut app = pending_app();
    let mut txt = txt_record("a=1");
    txt.flush_bit = false;
    txt.ttl = 1;
    txt.received_at = Instant::now() - Duration::from_secs(5);
    ingest(&mut app, &txt);
    let mut srv = srv_record(120);
    srv.flush_bit = false;
    ingest(&mut app, &srv); // promotes the pending instance
    assert!(!app.services.is_empty(), "promoted");
    assert!(stream_interval(&app, INSTANCE, 16) < MAX_CONTINUOUS_INTERVAL);
    assert_eq!(stream_interval(&app, INSTANCE, 33), MAX_CONTINUOUS_INTERVAL);
}
