// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #424: known answers in a query's Additional section (RFC 6762 §7.1) ---

use super::*;
use crate::browse::{Event, RecordSection};

const SERVICE: &str = "fritz-box._igd2._tcp.local";
const NAME: &str = "fritz-box._igd2._tcp.local.";
const SUFFIX: &str = "; responders suppress only on the Answer section";

fn querier() -> SocketAddr {
    "192.168.1.70:5353".parse().unwrap()
}

/// One question row as a query packet carries it.
fn question(name: &str, rtype: u16, rtype_str: &str, source: SocketAddr) -> RawRecord {
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
    q
}

/// A record the querier carries, in `section`.
fn carried(name: &str, rtype: u16, rtype_str: &str, section: RecordSection) -> RawRecord {
    let mut r = rec_with(
        name,
        rtype,
        rtype_str,
        "0 0 49000 fritz-box.fritz.box.",
        120,
        false,
        true,
        section,
    );
    r.source = querier();
    r
}

/// The SRV record the querier knows, misplaced.
fn misplaced_srv() -> RawRecord {
    carried(NAME, 33, "SRV", RecordSection::Additional)
}

/// A query carrying `questions` and `additional`.
fn packet(questions: Vec<RawRecord>, additional: Vec<RawRecord>) -> Event {
    let source = questions.first().map(|q| q.source).unwrap_or_else(querier);
    Event {
        answers: Vec::new(),
        questions,
        query_kas: Vec::new(),
        query_authority: Vec::new(),
        query_additional: additional,
        rcode: None,
        received_at: Instant::now(),
        raw_bytes: Vec::new(),
        source,
    }
}

/// The snapshot's Questions row for `q` under `service`.
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

fn findings(rows: Vec<QuestionView<'_>>, events: &[Event]) -> Vec<Anomaly> {
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
        .into_iter()
        .filter(|a| a.kind == AnomalyKind::MisplacedKnownAnswer)
        .collect()
}

#[test]
fn a_record_in_the_additional_section_is_flagged() {
    let q = question(NAME, 33, "SRV", querier());
    let events: Vec<_> = (0..3)
        .map(|_| packet(vec![q.clone()], vec![misplaced_srv()]))
        .collect();
    let found = findings(vec![row(SERVICE, &q)], &events);
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = &found[0];
    assert_eq!(f.severity, Severity::Warning);
    assert_eq!(f.rfc, "RFC 6762 §7.1");
    assert_eq!(f.requirement, "");
    assert_eq!(f.service, SERVICE);
    assert_eq!(f.record_name.as_deref(), Some(NAME));
    assert_eq!(f.rtype, Some(33));
    assert_eq!(f.source.as_deref(), Some("192.168.1.70:5353"));
    assert_eq!(
        f.message,
        format!("known answer {NAME} SRV in the Additional section of 3 queries{SUFFIX}")
    );
    assert!(AnomalyKind::MisplacedKnownAnswer.is_question());
    assert_eq!(
        AnomalyKind::MisplacedKnownAnswer.as_str(),
        "misplaced-known-answer"
    );
}

#[test]
fn only_queries_carrying_such_records_are_counted() {
    let q = question(NAME, 33, "SRV", querier());
    let events = vec![
        packet(vec![q.clone()], vec![misplaced_srv()]),
        packet(vec![q.clone()], Vec::new()),
        packet(vec![q.clone()], Vec::new()),
    ];
    let found = findings(vec![row(SERVICE, &q)], &events);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(
        found[0].message,
        format!("known answer {NAME} SRV in the Additional section of 1 query{SUFFIX}")
    );
}

#[test]
fn known_answers_in_the_answer_section_stay_quiet() {
    let q = question(NAME, 33, "SRV", querier());
    let mut ev = packet(vec![q.clone()], Vec::new());
    ev.query_kas = vec![carried(NAME, 33, "SRV", RecordSection::KnownAnswer)];
    let found = findings(vec![row(SERVICE, &q)], &[ev]);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn probes_stay_quiet() {
    let q = question(NAME, 255, "ANY", querier());
    let mut ev = packet(vec![q.clone()], vec![misplaced_srv()]);
    ev.query_authority = vec![carried(NAME, 33, "SRV", RecordSection::Authority)];
    let found = findings(vec![row(SERVICE, &q)], &[ev]);
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn one_shot_queriers_are_flagged() {
    let q = question(NAME, 33, "SRV", "192.168.1.70:49152".parse().unwrap());
    let found = findings(
        vec![row(SERVICE, &q)],
        &[packet(vec![q.clone()], vec![misplaced_srv()])],
    );
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].source.as_deref(), Some("192.168.1.70:49152"));
}

#[test]
fn every_question_of_the_query_is_marked() {
    let srv = question(NAME, 33, "SRV", querier());
    let txt = question(NAME, 16, "TXT", querier());
    let ev = packet(vec![srv.clone(), txt.clone()], vec![misplaced_srv()]);
    let found = findings(vec![row(SERVICE, &srv), row(SERVICE, &txt)], &[ev]);
    let mut types: Vec<_> = found.iter().map(|a| a.rtype).collect();
    types.sort();
    assert_eq!(types, vec![Some(16), Some(33)], "{found:#?}");
}

#[test]
fn several_records_are_summed_up_and_case_folded() {
    let q = question(NAME, 33, "SRV", querier());
    let upper = carried(
        "FRITZ-BOX._igd2._tcp.local.",
        33,
        "SRV",
        RecordSection::Additional,
    );
    let host = carried("fritz-box.fritz.box.", 1, "A", RecordSection::Additional);
    let events = vec![
        packet(vec![q.clone()], vec![misplaced_srv(), upper]),
        packet(vec![q.clone()], vec![host]),
    ];
    let found = findings(vec![row(SERVICE, &q)], &events);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(
        found[0].message,
        format!(
            "known answers {NAME} SRV and 1 more in the Additional section of 2 queries{SUFFIX}"
        )
    );
}

#[test]
fn other_queriers_are_not_blamed() {
    let q = question(NAME, 33, "SRV", querier());
    let other = question(NAME, 33, "SRV", "192.168.1.71:5353".parse().unwrap());
    let found = findings(
        vec![row(SERVICE, &q)],
        &[packet(vec![other], vec![misplaced_srv()])],
    );
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn an_enumeration_question_is_flagged_there() {
    let q = question(ENUM_SERVICE, 12, "PTR", querier());
    let ka = carried(ENUM_SERVICE, 12, "PTR", RecordSection::Additional);
    let found = findings(
        vec![row(ENUMERATION_SERVICE, &q)],
        &[packet(vec![q.clone()], vec![ka])],
    );
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].service, ENUMERATION_SERVICE);
}

/// A sighting row names its link: it counts that link's queries only.
#[test]
fn a_link_labelled_row_counts_its_own_link() {
    let q = question(NAME, 33, "SRV", querier());
    let on_link = |iface: &str, ifindex| {
        let mut q = q.clone();
        q.iface = iface.to_string();
        q.ifindex = ifindex;
        q
    };
    let (eth0, wlan0) = (on_link("eth0", 2), on_link("wlan0", 3));
    let events = vec![
        packet(vec![eth0.clone()], vec![misplaced_srv()]),
        packet(vec![wlan0.clone()], Vec::new()),
    ];
    let sighting = |q: &RawRecord| q.source_label();
    let rows = [&eth0, &wlan0]
        .into_iter()
        .map(|q| QuestionView {
            source_label: sighting(q),
            ..row(SERVICE, q)
        })
        .collect();
    let found = findings(rows, &events);
    let sources: Vec<_> = found.iter().map(|a| a.source.as_deref()).collect();
    assert_eq!(sources, vec![Some("192.168.1.70:5353@eth0")], "{found:#?}");
}
