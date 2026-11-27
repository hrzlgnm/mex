// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #408: questions repeated within one second (RFC 6762 §5.2) ---

use super::*;
use crate::browse::{Event, RecordSection};

const SERVICE: &str = "Inst._http._tcp.local";
const NAME: &str = "Inst._http._tcp.local.";

fn querier() -> SocketAddr {
    "192.168.1.70:5353".parse().unwrap()
}

/// A fixed point in the past that the events offset from.
fn base() -> Instant {
    Instant::now()
        .checked_sub(Duration::from_secs(60))
        .unwrap_or_else(Instant::now)
}

/// One question row as a query packet carries it.
fn question(name: &str, rtype: u16, rtype_str: &str, source: SocketAddr, iface: &str) -> RawRecord {
    let mut q = rec_with(
        name,
        rtype,
        rtype_str,
        "",
        0,
        false,
        true,
        RecordSection::Question,
    );
    q.source = source;
    q.iface = iface.to_string();
    q.ifindex = if iface.is_empty() { 0 } else { 2 };
    q
}

/// A query packet carrying `questions`, received `ms` after `base`.
fn query_at(at: Instant, ms: u64, questions: Vec<RawRecord>) -> Event {
    let received_at = at + Duration::from_millis(ms);
    let source = questions.first().map(|q| q.source).unwrap_or_else(querier);
    Event {
        answers: Vec::new(),
        questions: questions
            .into_iter()
            .map(|mut q| {
                q.received_at = received_at;
                q
            })
            .collect(),
        query_kas: Vec::new(),
        query_authority: Vec::new(),
        rcode: None,
        received_at,
        raw_bytes: Vec::new(),
        source,
    }
}

/// `source` asking `NAME` SRV on `iface` at each offset (ms).
fn askings(source: SocketAddr, iface: &str, offsets: &[u64]) -> Vec<Event> {
    let at = base();
    offsets
        .iter()
        .map(|ms| query_at(at, *ms, vec![question(NAME, 33, "SRV", source, iface)]))
        .collect()
}

/// The snapshot's Questions row for `q` under `service`.
fn row<'a>(service: &str, q: &'a RawRecord) -> QuestionView<'a> {
    QuestionView {
        service: service.to_string(),
        name: &q.name,
        rtype: q.rtype,
        rtype_str: &q.rtype_str,
        source: q.source,
        source_label: q.source_label(),
    }
}

/// Analyze `rows` (the observed questions) against `events`.
fn analyze_questions(rows: Vec<QuestionView<'_>>, events: &[Event]) -> Vec<Anomaly> {
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: Vec::new(),
        pending_hosts: HashSet::new(),
        questions: rows,
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    analyze_observations(&snap, events, &[])
}

fn rate_findings(found: &[Anomaly]) -> Vec<&Anomaly> {
    found
        .iter()
        .filter(|a| a.kind == AnomalyKind::QueryRateLimit)
        .collect()
}

#[test]
fn querier_repeating_a_question_within_a_second_is_flagged() {
    let q = question(NAME, 33, "SRV", querier(), "");
    let events = askings(querier(), "", &[0, 250, 500, 750, 1000]);
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    let rate = rate_findings(&found);
    assert_eq!(rate.len(), 1, "{found:#?}");
    let a = rate[0];
    assert_eq!(a.severity, Severity::Warning);
    assert_eq!(a.rfc, "RFC 6762 §5.2");
    assert_eq!(a.requirement, "MUST");
    assert_eq!(a.service, SERVICE);
    assert_eq!(a.record_name.as_deref(), Some(NAME));
    assert_eq!(a.rtype, Some(33));
    assert_eq!(a.source.as_deref(), Some("192.168.1.70:5353"));
    assert!(a.message.contains("asked 5 times in 1 s"), "{}", a.message);
    assert!(
        a.message.contains("as little as 0.25 s apart"),
        "{}",
        a.message
    );
}

#[test]
fn askings_a_second_or_more_apart_stay_quiet() {
    let q = question(NAME, 33, "SRV", querier(), "");
    // Exactly the floor, then the RFC 6762 §5.2 startup spacing.
    for offsets in [&[0, 1000, 2000][..], &[0, 1000, 3000, 7000][..]] {
        let events = askings(querier(), "", offsets);
        let found = analyze_questions(vec![row(SERVICE, &q)], &events);
        assert!(rate_findings(&found).is_empty(), "{offsets:?}: {found:#?}");
    }
}

#[test]
fn different_queriers_asking_close_together_stay_quiet() {
    let other: SocketAddr = "192.168.1.71:5353".parse().unwrap();
    let mine = question(NAME, 33, "SRV", querier(), "");
    let theirs = question(NAME, 33, "SRV", other, "");
    let mut events = askings(querier(), "", &[0]);
    events.extend(askings(other, "", &[250]));
    let found = analyze_questions(vec![row(SERVICE, &mine), row(SERVICE, &theirs)], &events);
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn one_querier_on_two_links_stays_quiet() {
    let on_eth = question(NAME, 33, "SRV", querier(), "eth0");
    let on_wlan = question(NAME, 33, "SRV", querier(), "wlan0");
    let mut events = askings(querier(), "eth0", &[0]);
    events.extend(askings(querier(), "wlan0", &[250]));
    let found = analyze_questions(vec![row(SERVICE, &on_eth), row(SERVICE, &on_wlan)], &events);
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn a_duplicate_question_in_one_packet_counts_once() {
    let q = question(NAME, 33, "SRV", querier(), "");
    let events = vec![query_at(base(), 0, vec![q.clone(), q.clone()])];
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn one_shot_queriers_stay_quiet() {
    let stub: SocketAddr = "192.168.1.70:45678".parse().unwrap();
    let q = question(NAME, 33, "SRV", stub, "");
    let events = askings(stub, "", &[0, 250, 500]);
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn probes_stay_quiet() {
    // RFC 6762 §8.1: three probes 250 ms apart, each with its proposed
    // record in the authority section.
    let q = question(NAME, 255, "ANY", querier(), "");
    let at = base();
    let events: Vec<Event> = [0, 250, 500]
        .iter()
        .map(|ms| {
            let mut ev = query_at(at, *ms, vec![q.clone()]);
            ev.query_authority = vec![rec(NAME, 33, "SRV", "0 0 80 host.local.", 120, false)];
            ev
        })
        .collect();
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn names_fold_ascii_case_only() {
    let q = question(NAME, 33, "SRV", querier(), "");
    let at = base();
    // ASCII case only: one question, asked twice 250 ms apart.
    let events = vec![
        query_at(at, 0, vec![question(NAME, 33, "SRV", querier(), "")]),
        query_at(
            at,
            250,
            vec![question("INST._HTTP._tcp.local.", 33, "SRV", querier(), "")],
        ),
    ];
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    assert_eq!(rate_findings(&found).len(), 1, "{found:#?}");
    // `É` and `é` are two names (§16): two questions, once each.
    let accented = question("Éclair._http._tcp.local.", 33, "SRV", querier(), "");
    let events = vec![
        query_at(at, 0, vec![accented.clone()]),
        query_at(
            at,
            250,
            vec![question(
                "éclair._http._tcp.local.",
                33,
                "SRV",
                querier(),
                "",
            )],
        ),
    ];
    let found = analyze_questions(vec![row(SERVICE, &accented)], &events);
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn an_enumeration_question_is_flagged_under_the_enumeration_row() {
    let q = question(ENUM_SERVICE, 12, "PTR", querier(), "");
    let at = base();
    let events: Vec<Event> = [0, 300]
        .iter()
        .map(|ms| query_at(at, *ms, vec![q.clone()]))
        .collect();
    let found = analyze_questions(vec![row(ENUMERATION_SERVICE, &q)], &events);
    let rate = rate_findings(&found);
    assert_eq!(rate.len(), 1, "{found:#?}");
    assert_eq!(rate[0].service, ENUMERATION_SERVICE);
    assert!(
        rate[0].message.contains("asked 2 times in 0.3 s"),
        "{}",
        rate[0].message
    );
}

#[test]
fn repeats_report_count_span_and_closest_gap() {
    let at = base();
    let ms = |n| at + Duration::from_millis(n);
    assert_eq!(
        crate::anomalies::rate::repeats(vec![ms(0)]),
        None,
        "one send"
    );
    assert_eq!(
        crate::anomalies::rate::repeats(vec![ms(0), ms(1000)]),
        None,
        "the floor"
    );
    assert_eq!(
        crate::anomalies::rate::repeats(vec![ms(2000), ms(0), ms(1800)]),
        Some(crate::anomalies::rate::Repeats {
            count: 3,
            span: Duration::from_millis(2000),
            min_gap: Duration::from_millis(200),
        })
    );
    assert_eq!(
        crate::anomalies::rate::fmt_secs(Duration::from_millis(6000)),
        "6"
    );
    assert_eq!(
        crate::anomalies::rate::fmt_secs(Duration::from_millis(250)),
        "0.25"
    );
    assert_eq!(
        crate::anomalies::rate::fmt_secs(Duration::from_millis(200)),
        "0.2"
    );
}
