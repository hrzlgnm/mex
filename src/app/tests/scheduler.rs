// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Scheduler rules on their own, without an App (#294).

use super::*;

fn key(name: &str, rtype: u16) -> (String, u16) {
    (name.to_string(), rtype)
}

fn seeded(name: &str, rtype: u16, interval: Duration, now: Instant) -> Scheduler {
    let mut s = Scheduler::default();
    s.continuous_mut().insert(
        key(name, rtype),
        ContinuousQuery {
            next_due: now,
            interval,
            qname: name.to_string(),
        },
    );
    s
}

#[test]
fn continuous_backoff_doubles_to_the_hourly_cap() {
    let now = Instant::now();
    let k = key("_http._tcp.local", 12);
    let mut s = seeded(&k.0, k.1, Duration::from_secs(1), now);
    let mut waits = Vec::new();
    for _ in 0..14 {
        s.advance_continuous(&k, now);
        waits.push(s.continuous()[&k].next_due - now);
    }
    assert_eq!(waits[0], Duration::from_secs(1));
    assert_eq!(waits[1], Duration::from_secs(2));
    assert_eq!(waits[2], Duration::from_secs(4));
    assert_eq!(*waits.last().unwrap(), MAX_CONTINUOUS_INTERVAL);
    assert!(waits.windows(2).all(|w| w[0] <= w[1]));
}

#[test]
fn refresh_postpones_the_stream_or_starts_one() {
    let now = Instant::now();
    let k = key("_http._tcp.local", 12);
    let mut s = seeded(&k.0, k.1, Duration::from_secs(8), now);
    s.postpone_continuous_for_refresh(&key("_HTTP._tcp.local", 12), now);
    assert_eq!(
        s.continuous()[&k].next_due,
        now + Duration::from_secs(8),
        "case-insensitive match is floored at now + interval"
    );

    let mut fresh = Scheduler::default();
    let host = key("printer.local", 1);
    fresh.postpone_continuous_for_refresh(&host, now);
    let entry = &fresh.continuous()[&Scheduler::continuous_key(&host.0, host.1)];
    assert_eq!(entry.next_due, now + Duration::from_secs(1));
    assert_eq!(entry.qname, "printer.local");
}

#[test]
fn overheard_question_suppresses_our_duplicate_once() {
    let q = raw_record("_ipp._tcp.local.", 12, "PTR", "", 0);
    let ka = raw_record(
        "_ipp._tcp.local.",
        12,
        "PTR",
        "printer._ipp._tcp.local.",
        4500,
    );
    let mut s = Scheduler::default();
    s.note_overheard(&q, std::slice::from_ref(&ka));
    let local = [browse::KnownAnswer {
        target: "Printer._ipp._tcp.local".to_string(),
        ttl: 4500,
        iface: String::new(),
    }];
    let k = key("_ipp._tcp.local", 12);
    assert!(s.suppressed_by_overheard(&k, &local), "remote KAs ⊆ ours");
    assert!(
        !s.suppressed_by_overheard(&k, &local),
        "an overheard question suppresses only once"
    );
}

#[test]
fn overheard_question_with_extra_known_answers_does_not_suppress() {
    let q = raw_record("_ipp._tcp.local.", 12, "PTR", "", 0);
    let kas = [
        raw_record("_ipp._tcp.local.", 12, "PTR", "a._ipp._tcp.local.", 4500),
        raw_record("_ipp._tcp.local.", 12, "PTR", "b._ipp._tcp.local.", 4500),
    ];
    let mut s = Scheduler::default();
    s.note_overheard(&q, &kas);
    let local = [browse::KnownAnswer {
        target: "a._ipp._tcp.local".to_string(),
        ttl: 4500,
        iface: String::new(),
    }];
    assert!(!s.suppressed_by_overheard(&key("_ipp._tcp.local", 12), &local));
}

#[test]
fn response_names_the_question_sent_just_before_it() {
    let answer = raw_record("printer.local.", 1, "A", "192.168.1.9", 120);
    let sent = answer
        .received_at
        .checked_sub(Duration::from_millis(300))
        .unwrap();
    let mut s = Scheduler::default();
    s.note_query(
        "printer.local",
        28,
        QueryOrigin::Transmitted,
        sent,
        "eth0".into(),
    );
    let trigger = s
        .response_trigger(&answer)
        .expect("own AAAA query within 1s");
    assert!(trigger.own);
    assert_eq!(trigger.question, "printer.local. AAAA");

    let late = answer
        .received_at
        .checked_sub(TRIGGER_WINDOW + Duration::from_millis(1))
        .unwrap();
    let mut stale = Scheduler::default();
    stale.note_query(
        "printer.local",
        28,
        QueryOrigin::Transmitted,
        late,
        "eth0".into(),
    );
    assert!(stale.response_trigger(&answer).is_none());
}

#[test]
fn refresh_postpones_the_stream_of_the_same_name_only() {
    // RFC 6762 §16: A-Z fold, other bytes compare exactly. A refresh in
    // another ASCII case postpones the stream of its name...
    let now = Instant::now();
    let stream = Scheduler::continuous_key("\u{00C9}clair._http._tcp.local", 33);
    let mut s = seeded(&stream.0, stream.1, Duration::from_secs(8), now);
    s.postpone_continuous_for_refresh(&key("\u{00C9}CLAIR._HTTP._tcp.local", 33), now);
    assert_eq!(
        s.continuous()[&stream].next_due,
        now + Duration::from_secs(8),
        "the existing stream is floored at now + its interval"
    );
    assert_eq!(
        s.continuous().len(),
        1,
        "no second stream for the same name"
    );
    // ...while `é` (U+00E9) is another name: its own stream starts,
    // and the `É` stream keeps its time.
    let later = now + Duration::from_secs(30);
    s.postpone_continuous_for_refresh(&key("\u{00E9}clair._http._tcp.local", 33), later);
    assert_eq!(s.continuous().len(), 2);
    assert_eq!(
        s.continuous()[&stream].next_due,
        now + Duration::from_secs(8)
    );
}
