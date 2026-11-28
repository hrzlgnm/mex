// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #408: questions repeated within one second (RFC 6762 §5.2) ---

use super::*;
use crate::browse::{Event, OwnSend, RecordSection};

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
        query_additional: Vec::new(),
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

/// The snapshot's Questions row for `q` under `service`, as the app
/// builds it: rows carry no ingress link, so the label is the address.
fn row<'a>(service: &str, q: &'a RawRecord) -> QuestionView<'a> {
    QuestionView {
        service: service.to_string(),
        name: &q.name,
        rtype: q.rtype,
        rtype_str: &q.rtype_str,
        source: q.source,
        source_label: q.source.to_string(),
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
    analyze_observations(&snap, events, &[], &[])
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
    // One Questions row (rows carry no link), asked once on each link.
    let q = question(NAME, 33, "SRV", querier(), "eth0");
    let mut events = askings(querier(), "eth0", &[0]);
    events.extend(askings(querier(), "wlan0", &[250]));
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
    // Two unnamed links stay apart too, by interface index.
    let mut first = askings(querier(), "", &[0]);
    let mut second = askings(querier(), "", &[250]);
    first[0].questions[0].ifindex = 3;
    second[0].questions[0].ifindex = 4;
    first.extend(second);
    let found = analyze_questions(vec![row(SERVICE, &q)], &first);
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn querier_repeating_on_a_named_link_is_flagged_on_its_row() {
    // Packets know their link; the Questions row doesn't. The repeats on
    // eth0 still land on the querier's row.
    let q = question(NAME, 33, "SRV", querier(), "eth0");
    let events = askings(querier(), "eth0", &[0, 300]);
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    let rate = rate_findings(&found);
    assert_eq!(rate.len(), 1, "{found:#?}");
    assert_eq!(rate[0].source.as_deref(), Some("192.168.1.70:5353"));
}

#[test]
fn a_gap_just_under_a_second_never_reads_as_one() {
    let q = question(NAME, 33, "SRV", querier(), "");
    let events = askings(querier(), "", &[0, 999]);
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    let rate = rate_findings(&found);
    assert_eq!(rate.len(), 1, "{found:#?}");
    assert!(
        rate[0].message.contains("as little as 0.99 s apart"),
        "{}",
        rate[0].message
    );
}

#[test]
fn an_opt_only_authority_section_is_no_probe() {
    // OPT belongs in the additional section; a query carrying only an
    // OPT in its authority section proposes nothing, so it isn't a probe.
    let q = question(NAME, 33, "SRV", querier(), "");
    let mut events = askings(querier(), "", &[0, 250]);
    for ev in &mut events {
        ev.query_authority = vec![rec("", 41, "OPT", "", 0, false)];
    }
    let found = analyze_questions(vec![row(SERVICE, &q)], &events);
    assert_eq!(rate_findings(&found).len(), 1, "{found:#?}");
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

// --- #407: records multicast again within one second (RFC 6762 §6) ---

const HOST: &str = "Repeater.local.";

fn responder() -> SocketAddr {
    "192.168.1.109:5353".parse().unwrap()
}

/// The repeater's A record as one response carries it.
fn host_a(source: SocketAddr, iface: &str) -> RawRecord {
    let mut r = rec_with(
        HOST,
        1,
        "A",
        "192.168.1.109",
        120,
        false,
        true,
        RecordSection::Additional,
    );
    r.source = source;
    r.iface = iface.to_string();
    r.ifindex = if iface.is_empty() { 0 } else { 2 };
    r
}

/// A response packet carrying `records`, received `ms` after `at`.
fn response_at(at: Instant, ms: u64, records: Vec<RawRecord>) -> Event {
    let received_at = at + Duration::from_millis(ms);
    let source = records.first().map(|r| r.source).unwrap_or_else(responder);
    Event {
        answers: records
            .into_iter()
            .map(|mut r| {
                r.received_at = received_at;
                r
            })
            .collect(),
        questions: Vec::new(),
        query_kas: Vec::new(),
        query_authority: Vec::new(),
        query_additional: Vec::new(),
        rcode: Some(0),
        received_at,
        raw_bytes: Vec::new(),
        source,
    }
}

/// `record` multicast at each offset (ms) from `at`, one response each.
/// Callers pass one `at` to every `sends` they combine, so their gaps
/// stay exact however long the test runs between calls.
fn sends(at: Instant, record: &RawRecord, offsets: &[u64]) -> Vec<Event> {
    offsets
        .iter()
        .map(|ms| response_at(at, *ms, vec![record.clone()]))
        .collect()
}

/// Analyze one service holding `answers` against `events`.
fn analyze_answers(answers: &[RawRecord], events: &[Event]) -> Vec<Anomaly> {
    analyze_answers_own(answers, events, &[])
}

/// `analyze_answers`, with our own sent query copies `own`.
fn analyze_answers_own(answers: &[RawRecord], events: &[Event], own: &[OwnSend]) -> Vec<Anomaly> {
    let snap = Snapshot {
        services: vec![ServiceView {
            instance: "Inst",
            service_type: "_http._tcp.local",
            answers,
            subtypes: &[],
            denied_address_types: Vec::new(),
        }],
        enum_answers: Vec::new(),
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    analyze_observations(&snap, events, own, &[])
}

fn multicast_findings(found: &[Anomaly]) -> Vec<&Anomaly> {
    found
        .iter()
        .filter(|a| a.kind == AnomalyKind::MulticastRateLimit)
        .collect()
}

/// The cached row: the latest copy of `r`.
fn cached(r: &RawRecord) -> RawRecord {
    let mut c = r.clone();
    c.received_at = base() + Duration::from_millis(1000);
    c
}

#[test]
fn record_multicast_twice_within_a_second_is_flagged() {
    let a = host_a(responder(), "");
    let at = base();
    let events = sends(at, &a, &[0, 250, 500, 750, 1000]);
    let found = analyze_answers(&[cached(&a)], &events);
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    let f = flood[0];
    assert_eq!(f.severity, Severity::Warning);
    assert_eq!(f.rfc, "RFC 6762 §6");
    assert_eq!(f.requirement, "MUST NOT");
    assert_eq!(f.service, SERVICE);
    assert_eq!(f.record_name.as_deref(), Some(HOST));
    assert_eq!(f.rtype, Some(1));
    assert_eq!(f.rdata.as_deref(), Some("192.168.1.109"));
    assert_eq!(f.source.as_deref(), Some("192.168.1.109:5353"));
    assert!(
        f.message.contains("multicast 5 times in 1 s"),
        "{}",
        f.message
    );
    assert!(
        f.message.contains("as little as 0.25 s apart"),
        "{}",
        f.message
    );
    assert!(
        !f.message.contains("answering"),
        "no trigger: {}",
        f.message
    );
}

#[test]
fn copies_a_second_or_more_apart_stay_quiet() {
    let a = host_a(responder(), "");
    // Exactly the floor, then RFC 6762 §8.3 announcements (1 s, doubling).
    for offsets in [&[0, 1000, 2000][..], &[0, 1000, 3000][..]] {
        let found = analyze_answers(&[cached(&a)], &sends(base(), &a, offsets));
        assert!(
            multicast_findings(&found).is_empty(),
            "{offsets:?}: {found:#?}"
        );
    }
}

#[test]
fn copies_from_two_sources_or_on_two_links_stay_quiet() {
    let other: SocketAddr = "192.168.1.110:5353".parse().unwrap();
    let mine = host_a(responder(), "");
    let theirs = host_a(other, "");
    let at = base();
    let mut events = sends(at, &mine, &[0]);
    events.extend(sends(at, &theirs, &[250]));
    let found = analyze_answers(&[cached(&mine), cached(&theirs)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");

    let on_eth = host_a(responder(), "eth0");
    let on_wlan = host_a(responder(), "wlan0");
    let at = base();
    let mut events = sends(at, &on_eth, &[0]);
    events.extend(sends(at, &on_wlan, &[250]));
    let found = analyze_answers(&[cached(&on_eth), cached(&on_wlan)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn a_duplicate_copy_in_one_packet_counts_once() {
    // The same record in the answer and additional sections.
    let a = host_a(responder(), "");
    let mut answer = a.clone();
    answer.section = RecordSection::Answer;
    let events = vec![response_at(base(), 0, vec![answer, a.clone()])];
    let found = analyze_answers(&[cached(&a)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn unicast_copies_and_goodbyes_are_ignored() {
    let a = host_a(responder(), "");
    let mut unicast = a.clone();
    unicast.dst_is_multicast = false;
    let at = base();
    let mut events = sends(at, &a, &[0]);
    events.extend(sends(at, &unicast, &[250]));
    let found = analyze_answers(&[cached(&a)], &events);
    assert!(multicast_findings(&found).is_empty(), "unicast: {found:#?}");

    let mut bye = a.clone();
    bye.ttl = 0;
    let at = base();
    let mut events = sends(at, &a, &[0]);
    events.extend(sends(at, &bye, &[250]));
    let found = analyze_answers(&[cached(&a)], &events);
    assert!(multicast_findings(&found).is_empty(), "goodbye: {found:#?}");
}

#[test]
fn a_probe_just_before_a_copy_exempts_it() {
    // Conflict defense (RFC 6762 §6): answering a probe for the name
    // right away is allowed, even within a second of the last copy.
    let a = host_a(responder(), "");
    let at = base();
    let prober: SocketAddr = "192.168.1.50:5353".parse().unwrap();
    let mut probe = query_at(at, 200, vec![question(HOST, 255, "ANY", prober, "")]);
    probe.query_authority = vec![host_a(prober, "")];
    let events = vec![
        response_at(at, 0, vec![a.clone()]),
        probe,
        response_at(at, 250, vec![a.clone()]),
    ];
    let found = analyze_answers(&[cached(&a)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn the_triggering_question_is_named() {
    // .70 asks another name; the repeater's response carries both that
    // answer and its own A record.
    let a = host_a(responder(), "");
    let srv = rec_with(
        "fritz-box._igd2._tcp.local.",
        33,
        "SRV",
        "0 0 49000 fritz.box.",
        120,
        true,
        true,
        RecordSection::Answer,
    );
    let mut srv = srv;
    srv.source = responder();
    let at = base();
    let ask = |ms| {
        query_at(
            at,
            ms,
            vec![question(
                "fritz-box._igd2._tcp.local.",
                33,
                "SRV",
                querier(),
                "",
            )],
        )
    };
    let events = vec![
        ask(0),
        response_at(at, 20, vec![srv.clone(), a.clone()]),
        ask(200),
        response_at(at, 220, vec![srv.clone(), a.clone()]),
    ];
    let found = analyze_answers(&[cached(&a)], &events);
    let flood = multicast_findings(&found);
    let host = flood
        .iter()
        .find(|f| f.record_name.as_deref() == Some(HOST))
        .unwrap_or_else(|| panic!("{found:#?}"));
    assert!(
        host.message
            .contains("answering 192.168.1.70:5353 asking fritz-box._igd2._tcp.local. SRV"),
        "{}",
        host.message
    );
}

/// The IPv6 twin of `querier()`: one device, two address families.
fn querier_v6() -> SocketAddr {
    "[fe80::8534:69b3:f34a:ac9d]:5353".parse().unwrap()
}

/// `record` from `source`, answering a query that `queriers` each sent
/// once per round (in that order, 0.1 ms apart), every 250 ms. Each
/// round's response follows the queries.
fn dual_stack_flood(record: &RawRecord, queriers: &[SocketAddr]) -> Vec<Event> {
    let at = base();
    let mut events = Vec::new();
    for round in 0..4u64 {
        let t = round * 250;
        for (i, src) in queriers.iter().enumerate() {
            let mut ev = query_at(at, t, vec![question(HOST, 1, "A", *src, "")]);
            ev.received_at += Duration::from_micros(100 * i as u64);
            events.push(ev);
        }
        events.push(response_at(at, t + 5, vec![record.clone()]));
    }
    events
}

/// Analyze one service holding `answers`, with `device_names` known.
fn analyze_answers_named(
    answers: &[RawRecord],
    events: &[Event],
    device_names: HashMap<std::net::IpAddr, DeviceLabel>,
) -> Vec<Anomaly> {
    let snap = Snapshot {
        services: vec![ServiceView {
            instance: "Inst",
            service_type: "_http._tcp.local",
            answers,
            subtypes: &[],
            denied_address_types: Vec::new(),
        }],
        enum_answers: Vec::new(),
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names,
    };
    analyze_observations(&snap, events, &[], &[])
}

/// The device `homeassistant.local`, matched exactly as `name`, or
/// inferred as `~name`.
fn device(name: &str) -> DeviceLabel {
    DeviceLabel {
        id: "homeassistant".to_string(),
        name: name.to_string(),
    }
}

fn flood_message(found: &[Anomaly]) -> String {
    let flood = multicast_findings(found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    flood[0].message.clone()
}

#[test]
fn a_dual_stack_querier_is_named_as_its_device() {
    // One device asks over IPv4 and IPv6 within a millisecond, in
    // either order: the trigger names the device and both addresses,
    // the same text whichever copy arrived last.
    let a = host_a(responder(), "");
    let names: HashMap<_, _> = [
        (querier().ip(), device("homeassistant")),
        (querier_v6().ip(), device("homeassistant")),
    ]
    .into();
    let want = "answering homeassistant (192.168.1.70:5353, [fe80::8534:69b3:f34a:ac9d]:5353) \
                asking Repeater.local. A";
    for order in [[querier(), querier_v6()], [querier_v6(), querier()]] {
        let events = dual_stack_flood(&a, &order);
        let msg = flood_message(&analyze_answers_named(
            &[cached(&a)],
            &events,
            names.clone(),
        ));
        assert!(msg.contains(want), "{msg}");
    }
}

#[test]
fn a_device_known_by_one_address_still_names_the_device() {
    // Only the IPv4 address resolves: the device wins even when the
    // unresolved IPv6 query is the latest.
    let a = host_a(responder(), "");
    let names: HashMap<_, _> = [(querier().ip(), device("homeassistant"))].into();
    let events = dual_stack_flood(&a, &[querier(), querier_v6()]);
    let msg = flood_message(&analyze_answers_named(&[cached(&a)], &events, names));
    assert!(
        msg.contains("answering homeassistant (192.168.1.70:5353) asking Repeater.local. A"),
        "{msg}"
    );
}

#[test]
fn an_exact_and_an_inferred_match_are_one_device() {
    // The IPv4 address matches exactly, the link-local one only by
    // interface ID (`~`): still one device, named by its exact match,
    // with both addresses, in either arrival order.
    let a = host_a(responder(), "");
    let names: HashMap<_, _> = [
        (querier().ip(), device("homeassistant")),
        (querier_v6().ip(), device("~homeassistant")),
    ]
    .into();
    let want = "answering homeassistant (192.168.1.70:5353, [fe80::8534:69b3:f34a:ac9d]:5353) \
                asking Repeater.local. A";
    for order in [[querier(), querier_v6()], [querier_v6(), querier()]] {
        let events = dual_stack_flood(&a, &order);
        let msg = flood_message(&analyze_answers_named(
            &[cached(&a)],
            &events,
            names.clone(),
        ));
        assert!(msg.contains(want), "{msg}");
    }
}

#[test]
fn an_unknown_querier_is_named_by_the_copy_s_family() {
    // No device known: an IPv4 copy names the IPv4 query and an IPv6
    // copy the IPv6 one, whichever arrived last.
    let v4 = host_a(responder(), "");
    let mut v6 = v4.clone();
    v6.source = "[fe80::ca0e:14ff:feff:416]:5353".parse().unwrap();
    for order in [[querier(), querier_v6()], [querier_v6(), querier()]] {
        let events = dual_stack_flood(&v4, &order);
        let msg = flood_message(&analyze_answers(&[cached(&v4)], &events));
        assert!(msg.contains("answering 192.168.1.70:5353 asking"), "{msg}");
        let events = dual_stack_flood(&v6, &order);
        let msg = flood_message(&analyze_answers(&[cached(&v6)], &events));
        assert!(
            msg.contains("answering [fe80::8534:69b3:f34a:ac9d]:5353 asking"),
            "{msg}"
        );
    }
}

#[test]
fn an_unknown_querier_of_the_other_family_is_still_named() {
    // Only an IPv6 query precedes an IPv4 copy: it is still the trigger.
    let a = host_a(responder(), "");
    let events = dual_stack_flood(&a, &[querier_v6()]);
    let msg = flood_message(&analyze_answers(&[cached(&a)], &events));
    assert!(
        msg.contains("answering [fe80::8534:69b3:f34a:ac9d]:5353 asking Repeater.local. A"),
        "{msg}"
    );
}

#[test]
fn record_names_fold_ascii_case_only() {
    let a = host_a(responder(), "");
    let mut upper = a.clone();
    upper.name = "REPEATER.local.".to_string();
    let at = base();
    let mut events = sends(at, &a, &[0]);
    events.extend(sends(at, &upper, &[250]));
    let found = analyze_answers(&[cached(&a)], &events);
    assert_eq!(multicast_findings(&found).len(), 1, "{found:#?}");

    let mut accented = a.clone();
    accented.name = "Répéteur.local.".to_string();
    let mut other = a.clone();
    other.name = "rÉpéteur.local.".to_string();
    let at = base();
    let mut events = sends(at, &accented, &[0]);
    events.extend(sends(at, &other, &[250]));
    let found = analyze_answers(&[cached(&accented)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn ptr_targets_fold_case_but_txt_data_does_not() {
    // An enumeration PTR whose target case varies is one record (ingest
    // replaces it by a case-folded target): its repeats still count.
    let mut ptr = rec(ENUM_SERVICE, 12, "PTR", "_ipp._tcp.local.", 4500, false);
    ptr.source = responder();
    let mut upper = ptr.clone();
    upper.rdata = "_IPP._tcp.local.".to_string();
    let at = base();
    let mut events = sends(at, &ptr, &[0]);
    events.extend(sends(at, &upper, &[250]));
    let row = cached(&upper);
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: vec![&row],
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    let found = analyze_observations(&snap, &events, &[], &[]);
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].service, ENUMERATION_SERVICE);

    // TXT data is case-sensitive: two different records, once each.
    let mut txt = rec(NAME, 16, "TXT", "a=1", 120, true);
    txt.source = responder();
    let mut other = txt.clone();
    other.rdata = "A=1".to_string();
    let at = base();
    let mut events = sends(at, &txt, &[0]);
    events.extend(sends(at, &other, &[250]));
    let found = analyze_answers(&[cached(&txt)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn name_valued_rdata_folds_case() {
    // An SRV target is a name: a responder varying its case still
    // repeats one record.
    let mut srv = rec(NAME, 33, "SRV", "0 0 80 Host.local.", 120, true);
    srv.source = responder();
    let mut upper = srv.clone();
    upper.rdata = "0 0 80 HOST.local.".to_string();
    let at = base();
    let mut events = sends(at, &srv, &[0]);
    events.extend(sends(at, &upper, &[250]));
    let found = analyze_answers(&[cached(&srv)], &events);
    assert_eq!(multicast_findings(&found).len(), 1, "{found:#?}");
}

#[test]
fn nsec_next_name_folds_case_but_bitmap_does_not() {
    // The NSEC next name is a name: varying its case still repeats one
    // record.
    let mut nsec = rec(NAME, 47, "NSEC", "Host.local. A AAAA", 120, true);
    nsec.source = responder();
    let mut upper = nsec.clone();
    upper.rdata = "HOST.local. A AAAA".to_string();
    let at = base();
    let events = vec![
        response_at(at, 0, vec![nsec.clone()]),
        response_at(at, 250, vec![upper]),
    ];
    let found = analyze_answers(&[cached(&nsec)], &events);
    assert_eq!(multicast_findings(&found).len(), 1, "{found:#?}");
    // A different bitmap is a different record, not a repeat.
    let mut fewer = nsec.clone();
    fewer.rdata = "host.local. A".to_string();
    let events = vec![
        response_at(at, 0, vec![nsec]),
        response_at(at, 250, vec![fewer.clone()]),
    ];
    let found = analyze_answers(&[cached(&fewer)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn opaque_records_compare_by_content_not_length() {
    // Out-of-scope records show only `rdlength=<n>`: two SOA copies of
    // one length but different serials are two records, not a repeat.
    let mut soa = rec("fritz.box.", 6, "TYPE6", "rdlength=49", 4500, false);
    soa.source = responder();
    soa.rdata_digest = Some(1);
    let mut bumped = soa.clone();
    bumped.rdata_digest = Some(2);
    let at = base();
    let mut events = sends(at, &soa, &[0]);
    events.extend(sends(at, &bumped, &[250]));
    let found = analyze_answers(&[cached(&bumped)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
    // The same content again is a repeat.
    let at = base();
    let mut events = sends(at, &soa, &[0]);
    events.extend(sends(at, &soa, &[250]));
    let found = analyze_answers(&[cached(&soa)], &events);
    assert_eq!(multicast_findings(&found).len(), 1, "{found:#?}");
}

#[test]
fn copies_on_two_unnamed_links_stay_quiet() {
    let mut on_three = host_a(responder(), "");
    on_three.ifindex = 3;
    let mut on_four = on_three.clone();
    on_four.ifindex = 4;
    let at = base();
    let mut events = sends(at, &on_three, &[0]);
    events.extend(sends(at, &on_four, &[250]));
    let found = analyze_answers(&[cached(&on_three), cached(&on_four)], &events);
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
}

#[test]
fn a_probe_answer_still_counts_as_the_last_multicast() {
    // RFC 6762 §6: the probe answer itself is allowed, but the next
    // multicast must still wait a second after it: 751 ms is too soon.
    let a = host_a(responder(), "");
    let at = base();
    let prober: SocketAddr = "192.168.1.50:5353".parse().unwrap();
    let mut probe = query_at(at, 200, vec![question(HOST, 255, "ANY", prober, "")]);
    probe.query_authority = vec![host_a(prober, "")];
    let events = vec![
        response_at(at, 0, vec![a.clone()]),
        probe,
        response_at(at, 250, vec![a.clone()]),
        response_at(at, 1001, vec![a.clone()]),
    ];
    let found = analyze_answers(&[cached(&a)], &events);
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert!(
        flood[0].message.contains("as little as 0.75 s apart"),
        "{}",
        flood[0].message
    );
}

/// `events` re-stamped with a header whose OPCODE is `opcode`, QR set
/// for responses.
fn with_opcode(events: Vec<Event>, opcode: u8) -> Vec<Event> {
    events
        .into_iter()
        .map(|mut ev| {
            let qr = if ev.questions.is_empty() { 0x84 } else { 0 };
            ev.raw_bytes = vec![0, 0, qr | (opcode << 3), 0, 0, 0, 0, 0, 0, 0, 0, 0];
            ev
        })
        .collect()
}

/// RFC 6762 §18.3 (#427): a message with a non-zero OPCODE is ignored,
/// so neither a question nor a record flood counts it.
#[test]
fn nonzero_opcode_floods_are_ignored() {
    let q = question(NAME, 33, "SRV", querier(), "");
    let askings = askings(querier(), "", &[0, 250, 500, 750, 1000]);
    let found = analyze_questions(vec![row(SERVICE, &q)], &with_opcode(askings.clone(), 5));
    assert!(rate_findings(&found).is_empty(), "{found:#?}");
    let found = analyze_questions(vec![row(SERVICE, &q)], &with_opcode(askings, 0));
    assert_eq!(rate_findings(&found).len(), 1, "{found:#?}");

    let a = host_a(responder(), "");
    let copies = sends(base(), &a, &[0, 250, 500, 750, 1000]);
    let found = analyze_answers(&[cached(&a)], &with_opcode(copies.clone(), 5));
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");
    let found = analyze_answers(&[cached(&a)], &with_opcode(copies, 0));
    assert_eq!(multicast_findings(&found).len(), 1, "{found:#?}");
}

// --- #431: mex's own queries as the trigger ---

/// Our own query copy asking `name` (as the app sends it: no trailing
/// dot) for `rtype` on `iface` (index 2 for `eth0`, as `host_a` has it,
/// else 3), sent `ms` after `at`.
fn own_at(at: Instant, ms: u64, name: &str, rtype: u16, iface: &str) -> OwnSend {
    OwnSend {
        questions: vec![(name.to_string(), rtype)],
        iface: iface.to_string(),
        ifindex: if iface == "eth0" { 2 } else { 3 },
        v6: false,
        sent_at: at + Duration::from_millis(ms),
    }
}

/// The repeater's A record on `eth0`, multicast at each offset (ms).
fn eth0_copies(at: Instant, offsets: &[u64]) -> (RawRecord, Vec<Event>) {
    let a = host_a(responder(), "eth0");
    let events = sends(at, &a, offsets);
    (a, events)
}

fn own_flood_message(a: &RawRecord, events: &[Event], own: &[OwnSend]) -> String {
    let found = analyze_answers_own(&[cached(a)], events, own);
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    flood[0].message.clone()
}

#[test]
fn our_query_right_before_the_repeats_names_mex() {
    let at = base();
    let (a, events) = eth0_copies(at, &[20, 270, 520]);
    let own: Vec<_> = [0, 250, 500]
        .map(|ms| own_at(at, ms, "Repeater.local", 1, "eth0"))
        .into();
    assert_eq!(
        own_flood_message(&a, &events, &own),
        "multicast 3 times in 0.5 s, as little as 0.25 s apart, \
         3 of 3 after mex's own queries, answering mex (this host) asking Repeater.local. A"
    );
}

#[test]
fn a_foreign_query_after_ours_wins_the_trigger() {
    let at = base();
    let a = host_a(responder(), "eth0");
    let ask = |ms| query_at(at, ms, vec![question(HOST, 1, "A", querier(), "eth0")]);
    let events = vec![
        ask(10),
        response_at(at, 20, vec![a.clone()]),
        ask(260),
        response_at(at, 270, vec![a.clone()]),
    ];
    let own = [
        own_at(at, 0, "Repeater.local", 1, "eth0"),
        own_at(at, 250, "Repeater.local", 1, "eth0"),
    ];
    let message = own_flood_message(&a, &events, &own);
    assert!(
        message.ends_with(
            ", 2 of 2 after mex's own queries, \
             answering 192.168.1.70:5353@eth0 asking Repeater.local. A"
        ),
        "{message}"
    );
}

#[test]
fn our_query_on_another_link_or_for_another_name_is_ignored() {
    let at = base();
    let (a, events) = eth0_copies(at, &[20, 270]);
    let own = [
        own_at(at, 0, "Repeater.local", 1, "wlan0"),
        own_at(at, 250, "other.local", 1, "eth0"),
    ];
    assert_eq!(
        own_flood_message(&a, &events, &own),
        "multicast 2 times in 0.25 s, as little as 0.25 s apart"
    );
}

/// A link removed and re-created under the same name gets a new index:
/// a send on the old one never answers a copy on the new one.
#[test]
fn our_query_on_a_same_named_link_with_another_index_is_ignored() {
    let at = base();
    let (a, events) = eth0_copies(at, &[20, 270]);
    let mut old_eth0 = own_at(at, 0, "Repeater.local", 1, "eth0");
    old_eth0.ifindex = 7;
    assert_eq!(
        own_flood_message(&a, &events, &[old_eth0]),
        "multicast 2 times in 0.25 s, as little as 0.25 s apart"
    );
}

#[test]
fn our_query_more_than_a_second_before_is_ignored() {
    let at = base();
    let (a, events) = eth0_copies(at, &[1100, 1300]);
    let own = [own_at(at, 0, "Repeater.local", 1, "eth0")];
    assert_eq!(
        own_flood_message(&a, &events, &own),
        "multicast 2 times in 0.2 s, as little as 0.2 s apart"
    );
}

#[test]
fn our_queries_match_names_ignoring_ascii_case_and_both_families_count() {
    let at = base();
    let (a, events) = eth0_copies(at, &[20, 270]);
    let mut v6 = own_at(at, 250, "REPEATER.local.", 1, "eth0");
    v6.v6 = true;
    let own = [own_at(at, 0, "repeater.local", 1, "eth0"), v6];
    let message = own_flood_message(&a, &events, &own);
    assert!(
        message.ends_with(
            ", 2 of 2 after mex's own queries, answering mex (this host) asking REPEATER.local. A"
        ),
        "{message}"
    );
}

#[test]
fn a_mixed_history_counts_only_the_copies_after_our_queries() {
    let at = base();
    let (a, events) = eth0_copies(at, &[1500, 1750, 2000, 2250]);
    // Our queries before the first two copies only, each within a second.
    let own = [
        own_at(at, 1400, "Repeater.local", 1, "eth0"),
        own_at(at, 1700, "Repeater.local", 1, "eth0"),
    ];
    let message = own_flood_message(&a, &events, &own);
    assert!(
        message.contains(", 4 of 4 after mex's own queries"),
        "every copy within a second of one: {message}"
    );
    let (a, events) = eth0_copies(at, &[0, 250, 1500, 1750]);
    let own = [own_at(at, 200, "Repeater.local", 1, "eth0")];
    let message = own_flood_message(&a, &events, &own);
    assert!(
        message.contains(", 1 of 4 after mex's own queries"),
        "{message}"
    );
    // The trigger comes from the latest copy that has one, as before:
    // here the one at 250 ms, after our query.
    assert!(
        message.ends_with("answering mex (this host) asking Repeater.local. A"),
        "{message}"
    );
}

#[test]
fn probe_answers_are_neither_judged_nor_attributed_to_us() {
    let at = base();
    let a = host_a(responder(), "eth0");
    let prober: SocketAddr = "192.168.1.50:5353".parse().unwrap();
    let mut probe = query_at(at, 1350, vec![question(HOST, 255, "ANY", prober, "eth0")]);
    probe.query_authority = vec![host_a(prober, "eth0")];
    let events = vec![
        response_at(at, 0, vec![a.clone()]),
        response_at(at, 300, vec![a.clone()]),
        probe,
        response_at(at, 1360, vec![a.clone()]),
    ];
    // Ours right before the probe answer only.
    let own = [own_at(at, 1355, "Repeater.local", 1, "eth0")];
    assert_eq!(
        own_flood_message(&a, &events, &own),
        "multicast 3 times in 1.36 s, as little as 0.3 s apart"
    );
}

#[test]
fn without_own_sends_the_text_is_unchanged() {
    let at = base();
    let (a, events) = eth0_copies(at, &[0, 250, 500, 750, 1000]);
    assert_eq!(
        own_flood_message(&a, &events, &[]),
        "multicast 5 times in 1 s, as little as 0.25 s apart"
    );
}

/// A packed query (#430) asks A and AAAA of one name together: the
/// trigger names the question the copy answers, not the first one.
#[test]
fn a_packed_query_names_the_question_the_copy_answers() {
    let at = base();
    let (a, events) = eth0_copies(at, &[20, 270]);
    let packed = |ms| OwnSend {
        questions: vec![
            ("Repeater.local".to_string(), 28),
            ("Repeater.local".to_string(), 1),
        ],
        ..own_at(at, ms, "unused", 0, "eth0")
    };
    let message = own_flood_message(&a, &events, &[packed(0), packed(250)]);
    assert!(
        message.ends_with("answering mex (this host) asking Repeater.local. A"),
        "{message}"
    );

    // The same for another querier's packed query.
    let a = host_a(responder(), "eth0");
    let ask = |ms| {
        query_at(
            at,
            ms,
            vec![
                question(HOST, 28, "AAAA", querier(), "eth0"),
                question(HOST, 1, "A", querier(), "eth0"),
            ],
        )
    };
    let events = vec![
        ask(0),
        response_at(at, 20, vec![a.clone()]),
        ask(250),
        response_at(at, 270, vec![a.clone()]),
    ];
    let message = own_flood_message(&a, &events, &[]);
    assert!(
        message.ends_with("answering 192.168.1.70:5353@eth0 asking Repeater.local. A"),
        "{message}"
    );
}

// --- #442: copies per query, and one finding per bursting responder ---

/// Analyze one service holding `answers` against `events`, with our own
/// sends `own`, `device_names` known and `hosts` heading the pane.
fn analyze_full(
    answers: &[RawRecord],
    events: &[Event],
    own: &[OwnSend],
    device_names: HashMap<std::net::IpAddr, DeviceLabel>,
    hosts: &[&str],
) -> Vec<Anomaly> {
    let snap = Snapshot {
        services: vec![ServiceView {
            instance: "Inst",
            service_type: "_http._tcp.local",
            answers,
            subtypes: &[],
            denied_address_types: Vec::new(),
        }],
        enum_answers: Vec::new(),
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: hosts
            .iter()
            .map(|h| HostAddressView {
                host: h.to_string(),
                records: Vec::new(),
            })
            .collect(),
        device_names,
    };
    analyze_observations(&snap, events, own, &[])
}

/// One query for HOST A at `ms`, answered by `copies` copies of `a`, the
/// first 5 ms later and then 7 ms apart.
fn answered_in_burst(at: Instant, ms: u64, a: &RawRecord, copies: u64) -> Vec<Event> {
    let mut events = vec![query_at(
        at,
        ms,
        vec![question(HOST, 1, "A", querier(), "eth0")],
    )];
    for i in 0..copies {
        events.push(response_at(at, ms + 5 + 7 * i, vec![a.clone()]));
    }
    events
}

/// The repeater device, its host heading the pane.
fn repeater_device() -> HashMap<std::net::IpAddr, DeviceLabel> {
    [(
        responder().ip(),
        DeviceLabel {
            id: "repeater".to_string(),
            name: "Repeater.local".to_string(),
        },
    )]
    .into()
}

#[test]
fn a_responder_answering_one_query_three_times_gets_one_host_finding() {
    let at = base();
    let a = host_a(responder(), "eth0");
    let events = answered_in_burst(at, 0, &a, 3);
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(
        flood.len(),
        1,
        "no row finding, one responder finding: {found:#?}"
    );
    let f = flood[0];
    assert_eq!(f.service, "repeater", "on the host header");
    assert_eq!(f.record_name, None);
    assert_eq!(f.severity, Severity::Warning);
    assert_eq!(f.rfc, "RFC 6762 §6");
    assert_eq!(
        f.message,
        "Repeater.local (192.168.1.109:5353@eth0) sends its answers up to 3 times per query, \
         within 14 ms (1 query, 1 record)"
    );
}

#[test]
fn a_bursting_responder_without_a_host_header_files_unattributed() {
    let at = base();
    let a = host_a(responder(), "eth0");
    let events = answered_in_burst(at, 0, &a, 2);
    let found = analyze_full(&[cached(&a)], &events, &[], HashMap::new(), &[]);
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].service, UNATTRIBUTED_SERVICE);
    assert!(
        flood[0]
            .message
            .starts_with("192.168.1.109 (192.168.1.109:5353@eth0) sends"),
        "{}",
        flood[0].message
    );
}

#[test]
fn our_own_query_counts_as_the_burst_trigger() {
    let at = base();
    let a = host_a(responder(), "eth0");
    let events = vec![
        response_at(at, 5, vec![a.clone()]),
        response_at(at, 12, vec![a.clone()]),
    ];
    let own = [own_at(at, 0, "Repeater.local", 1, "eth0")];
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &own,
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].record_name, None);
}

#[test]
fn bursts_for_two_queries_within_a_second_keep_the_row_finding() {
    // Re-multicasting for a second query 250 ms later is a repeat of its
    // own (§6): the row keeps its finding, which now counts the copies
    // per query, and no responder finding stands in for it.
    let at = base();
    let a = host_a(responder(), "eth0");
    let mut events = answered_in_burst(at, 0, &a, 3);
    events.extend(answered_in_burst(at, 250, &a, 3));
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].record_name.as_deref(), Some(HOST));
    assert!(
        flood[0].message.contains(", up to 3 copies per query"),
        "{}",
        flood[0].message
    );
    // The shortest gap is the one between the queries' answers, from the
    // first copy of each burst (5 ms to 255 ms), not one inside a burst.
    assert!(
        flood[0]
            .message
            .starts_with("multicast 6 times in 0.26 s, as little as 0.25 s apart"),
        "{}",
        flood[0].message
    );
}

#[test]
fn one_copy_per_query_adds_no_per_query_count() {
    let at = base();
    let a = host_a(responder(), "eth0");
    let mut events = answered_in_burst(at, 0, &a, 1);
    events.extend(answered_in_burst(at, 250, &a, 1));
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert!(
        !flood[0].message.contains("per query"),
        "{}",
        flood[0].message
    );
}

#[test]
fn unsolicited_copies_are_never_a_burst() {
    // No query before them: nothing to answer several times, so the row
    // keeps its finding and no responder finding appears.
    let at = base();
    let a = host_a(responder(), "eth0");
    let events = sends(at, &a, &[0, 7, 14]);
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].record_name.as_deref(), Some(HOST));
    assert!(
        !flood[0].message.contains("per query"),
        "{}",
        flood[0].message
    );
}

#[test]
fn a_responder_finding_sums_records_across_families() {
    // The same device answers over IPv4 and IPv6, each burst on its own
    // family: one finding naming both addresses. The querier asked over
    // both families 1 ms apart, which is one round.
    let at = base();
    let v6: SocketAddr = "[fe80::1:2:3:4]:5353".parse().unwrap();
    let a4 = host_a(responder(), "eth0");
    let mut a6 = host_a(v6, "eth0");
    a6.rtype = 28;
    a6.rtype_str = "AAAA".to_string();
    a6.rdata = "fe80::1:2:3:4".to_string();
    let mut events = answered_in_burst(at, 0, &a4, 3);
    let mut q6 = question(HOST, 28, "AAAA", querier_v6(), "eth0");
    q6.ifindex = 2;
    events.push(query_at(at, 1, vec![q6]));
    events.push(response_at(at, 6, vec![a6.clone()]));
    events.push(response_at(at, 9, vec![a6.clone()]));
    // The analyzer reads events in arrival order, as the listener queues them.
    events.sort_by_key(|ev| ev.received_at);
    let mut names = repeater_device();
    names.insert(v6.ip(), names[&responder().ip()].clone());
    let found = analyze_full(
        &[cached(&a4), cached(&a6)],
        &events,
        &[],
        names,
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(
        flood[0].source.as_deref(),
        Some(format!("{}, {}", a4.source_label(), a6.source_label()).as_str()),
        "both addresses, sorted"
    );
    assert!(
        flood[0].message.ends_with("(1 query, 2 records)"),
        "{}",
        flood[0].message
    );
}

#[test]
fn bursts_a_second_apart_leave_only_the_responder_finding() {
    // Queries one second apart, each answered by a 74 ms burst: the last
    // copy of one burst and the first of the next are under a second
    // apart, but the answers themselves are a second apart. Only the
    // duplicates are wrong, and the responder finding reports them.
    let at = base();
    let a = host_a(responder(), "eth0");
    let mut events = Vec::new();
    for round in 0..3u64 {
        let ms = 1000 * round;
        events.push(query_at(
            at,
            ms,
            vec![question(HOST, 1, "A", querier(), "eth0")],
        ));
        for offset in [5, 40, 79] {
            events.push(response_at(at, ms + offset, vec![a.clone()]));
        }
    }
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].record_name, None, "{}", flood[0].message);
    assert!(
        flood[0]
            .message
            .contains("up to 3 times per query, within 74 ms (3 queries, 1 record)"),
        "{}",
        flood[0].message
    );
}

#[test]
fn queries_a_few_ms_apart_are_one_round() {
    // A querier sending its questions in packets 10 ms apart, each
    // answered with the same record before the next arrives: three copies
    // with three distinct triggers, all inside one reply delay, so one
    // round answered three times.
    let at = base();
    let a = host_a(responder(), "eth0");
    let mut events = Vec::new();
    for ms in [0, 10, 20] {
        events.push(query_at(
            at,
            ms,
            vec![question(HOST, 1, "A", querier(), "eth0")],
        ));
        events.push(response_at(at, ms + 5, vec![a.clone()]));
    }
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].record_name, None, "{}", flood[0].message);
}

#[test]
fn answers_a_reply_delay_short_of_a_second_stay_quiet() {
    // Queries one second apart, answered after 120 ms and then 70 ms:
    // the answers are 0.95 s apart, within the reply delay RFC 6762 §6
    // allows, so no finding.
    let at = base();
    let a = host_a(responder(), "eth0");
    let events = vec![
        query_at(at, 0, vec![question(HOST, 1, "A", querier(), "eth0")]),
        response_at(at, 120, vec![a.clone()]),
        query_at(at, 1000, vec![question(HOST, 1, "A", querier(), "eth0")]),
        response_at(at, 1070, vec![a.clone()]),
    ];
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    assert!(multicast_findings(&found).is_empty(), "{found:#?}");

    // 0.85 s apart is past that tolerance: the row is flagged.
    let events = vec![
        query_at(at, 0, vec![question(HOST, 1, "A", querier(), "eth0")]),
        response_at(at, 120, vec![a.clone()]),
        query_at(at, 900, vec![question(HOST, 1, "A", querier(), "eth0")]),
        response_at(at, 970, vec![a.clone()]),
    ];
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].record_name.as_deref(), Some(HOST));
}

#[test]
fn a_probe_answer_after_a_burst_is_no_re_send() {
    // RFC 6762 §6: answering a probe may come early. After a burst for a
    // query, a probe answer 200 ms later doesn't count as multicasting the
    // record again, so only the responder finding remains.
    let at = base();
    let a = host_a(responder(), "eth0");
    let mut events = answered_in_burst(at, 0, &a, 2);
    let prober: SocketAddr = "192.168.1.50:5353".parse().unwrap();
    let mut probe = query_at(at, 200, vec![question(HOST, 255, "ANY", prober, "eth0")]);
    probe.query_authority = vec![host_a(prober, "eth0")];
    events.push(probe);
    events.push(response_at(at, 210, vec![a.clone()]));
    let found = analyze_full(
        &[cached(&a)],
        &events,
        &[],
        repeater_device(),
        &["repeater"],
    );
    let flood = multicast_findings(&found);
    assert_eq!(flood.len(), 1, "{found:#?}");
    assert_eq!(flood[0].record_name, None, "{}", flood[0].message);
}
