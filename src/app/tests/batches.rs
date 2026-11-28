// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #430: the questions of one tick leave as one batch ---

use super::*;

/// Every batch handed over so far, as `(name, type)` lists.
fn batches(rx: &mpsc::Receiver<browse::QueryBatch>) -> Vec<Vec<(String, u16)>> {
    rx.try_iter()
        .map(|batch| {
            batch
                .iter()
                .map(|q| (q.name.clone(), u16::from(q.record_type)))
                .collect()
        })
        .collect()
}

/// Make every stream due now, as time passing would.
fn all_due(app: &mut App) {
    let now = Instant::now() - Duration::from_millis(1);
    for entry in app.scheduler.continuous_mut().values_mut() {
        entry.next_due = now;
    }
}

#[test]
fn questions_learned_together_share_their_first_due_time() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500)); // pending: SRV/TXT wanted
    app.send_queries();
    let due: Vec<_> = app
        .scheduler
        .continuous()
        .values()
        .map(|e| e.next_due)
        .collect();
    assert!(due.len() > 1, "{due:?}");
    assert!(
        due.iter().all(|d| *d == due[0]),
        "one shared delay: {due:?}"
    );
}

#[test]
fn one_tick_hands_over_one_batch_and_counts_questions() {
    let mut app = App::new().unwrap();
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    all_due(&mut app);
    let streams = app.scheduler.continuous().len();
    let sent_before = app.diagnostics.q_sent_continuous;
    app.send_queries();
    let handed = batches(&rx);
    assert_eq!(handed.len(), 1, "{handed:?}");
    assert_eq!(handed[0].len(), streams, "{handed:?}");
    assert!(handed[0].contains(&("Test._http._tcp.local".to_string(), 33)));
    assert!(handed[0].contains(&("Test._http._tcp.local".to_string(), 16)));
    assert_eq!(
        app.diagnostics.q_sent_continuous,
        sent_before + streams as u64,
        "counters still count questions"
    );
    // Each question is noted as transmitted.
    let srv = app
        .scheduler
        .history(&Scheduler::provenance_key("test._http._tcp.local", 33));
    assert!(srv.is_some_and(|h| h.transmitted.is_some()));
}

#[test]
fn streams_started_together_stay_aligned_as_they_double() {
    let mut app = App::new().unwrap();
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    for _ in 0..3 {
        all_due(&mut app);
        app.send_queries();
    }
    assert_eq!(batches(&rx).len(), 3, "one batch per round");
    let timing: Vec<_> = app
        .scheduler
        .continuous()
        .values()
        .map(|e| (e.interval, e.next_due))
        .collect();
    assert!(
        timing
            .iter()
            .all(|t| t.0 == Duration::from_secs(8) && *t == timing[0]),
        "{timing:?}"
    );
}

#[test]
fn a_question_queued_twice_in_one_tick_goes_in_once() {
    let mut app = App::new().unwrap();
    let ka = |target: &str| browse::KnownAnswer {
        target: target.to_string(),
        ttl: 4500,
        iface: "eth0".to_string(),
    };
    let ptr = |name: &str, qu, kas| browse::QueryRequest {
        name: name.to_string(),
        record_type: TYPE::PTR,
        known_answers: kas,
        qu,
        links: Vec::new(),
    };
    app.queue_question(ptr(
        "_http._tcp.local",
        false,
        vec![ka("A._http._tcp.local")],
    ));
    app.queue_question(ptr(
        "_HTTP._tcp.local.",
        true,
        vec![ka("a._http._tcp.local"), ka("B._http._tcp.local")],
    ));
    assert_eq!(app.outbox.len(), 1);
    let q = &app.outbox[0];
    assert_eq!(q.name, "_http._tcp.local", "the first keeps its name");
    assert!(q.qu, "the QU bit sticks");
    let targets: Vec<_> = q.known_answers.iter().map(|k| k.target.as_str()).collect();
    assert_eq!(targets, ["A._http._tcp.local", "B._http._tcp.local"]);
}

#[test]
fn an_overheard_question_stays_out_of_the_batch() {
    // RFC 6762 §7.3: another querier just asked the SRV with no known
    // answer we'd send, so ours counts as sent and is left out.
    let mut app = App::new().unwrap();
    let rx = capture(&mut app);
    ingest(&mut app, &ptr_record(4500));
    app.send_queries();
    let ev = query_event(
        "Test._http._tcp.local.",
        33,
        "SRV",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    all_due(&mut app);
    app.send_queries();
    let handed = batches(&rx);
    assert_eq!(handed.len(), 1);
    assert!(!handed[0].iter().any(|(_, t)| *t == 33), "{handed:?}");
    assert_eq!(app.diagnostics.suppressed_continuous, 1);
    let srv = app
        .scheduler
        .history(&Scheduler::provenance_key("test._http._tcp.local", 33))
        .expect("the suppression is on record");
    assert!(srv.transmitted.is_none());
}

#[test]
fn nothing_is_handed_over_in_passive_mode_or_on_hold() {
    let mut passive = App::new_with(true, None).unwrap();
    let rx = capture(&mut passive);
    ingest(&mut passive, &ptr_record(4500));
    passive.send_queries();
    all_due(&mut passive);
    passive.send_queries();
    assert!(batches(&rx).is_empty());

    let mut held = App::new().unwrap();
    let rx = capture(&mut held);
    ingest(&mut held, &ptr_record(4500));
    held.query_tx.transmit().pin(false, false);
    held.send_queries();
    all_due(&mut held);
    held.send_queries();
    assert!(batches(&rx).is_empty());
    assert!(held.outbox.is_empty());
}
