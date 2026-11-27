// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #423: queries with the AA bit set (RFC 6762 §18.4) ---

use super::*;
use crate::browse::{Event, RecordSection};

const SERVICE: &str = "Inst._http._tcp.local";
const NAME: &str = "Inst._http._tcp.local.";

/// DNS header flags byte (byte 2): QR and AA.
const QR: u8 = 0x80;
const AA: u8 = 0x04;

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

/// A packet carrying `questions` whose header flags byte is `flags`.
fn packet(flags: u8, questions: Vec<RawRecord>) -> Event {
    let source = questions.first().map(|q| q.source).unwrap_or_else(querier);
    Event {
        answers: Vec::new(),
        questions,
        query_kas: Vec::new(),
        query_authority: Vec::new(),
        query_additional: Vec::new(),
        rcode: (flags & QR != 0).then_some(0),
        received_at: Instant::now(),
        raw_bytes: vec![0, 0, flags, 0, 0, 1, 0, 0, 0, 0, 0, 0],
        source,
    }
}

/// `n` queries of `q`, the first `aa` of them with the AA bit set.
fn queries(q: &RawRecord, n: usize, aa: usize) -> Vec<Event> {
    (0..n)
        .map(|i| packet(if i < aa { AA } else { 0 }, vec![q.clone()]))
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
        source_label: q.source.to_string(),
    }
}

fn aa_findings(rows: Vec<QuestionView<'_>>, events: &[Event]) -> Vec<Anomaly> {
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
        .into_iter()
        .filter(|a| a.kind == AnomalyKind::QueryAaBit)
        .collect()
}

#[test]
fn a_query_with_the_aa_bit_is_flagged() {
    let q = question(NAME, 33, "SRV", querier());
    let found = aa_findings(vec![row(SERVICE, &q)], &queries(&q, 3, 3));
    assert_eq!(found.len(), 1, "{found:#?}");
    let f = &found[0];
    assert_eq!(f.severity, Severity::Warning);
    assert_eq!(f.rfc, "RFC 6762 §18.4");
    assert_eq!(f.requirement, "MUST");
    assert_eq!(f.service, SERVICE);
    assert_eq!(f.record_name.as_deref(), Some(NAME));
    assert_eq!(f.rtype, Some(33));
    assert_eq!(f.source.as_deref(), Some("192.168.1.70:5353"));
    assert_eq!(
        f.message,
        "AA bit set in 3 of 3 queries (must be zero in queries)"
    );
    assert!(AnomalyKind::QueryAaBit.is_question());
    assert_eq!(AnomalyKind::QueryAaBit.as_str(), "query-aa-bit");
}

#[test]
fn a_mix_counts_only_the_aa_queries() {
    let q = question(NAME, 33, "SRV", querier());
    let found = aa_findings(vec![row(SERVICE, &q)], &queries(&q, 5, 2));
    assert_eq!(found.len(), 1, "{found:#?}");
    assert!(
        found[0].message.starts_with("AA bit set in 2 of 5 queries"),
        "{}",
        found[0].message
    );
    let found = aa_findings(vec![row(SERVICE, &q)], &queries(&q, 1, 1));
    assert!(
        found[0].message.starts_with("AA bit set in 1 of 1 query "),
        "{}",
        found[0].message
    );
}

#[test]
fn queries_without_the_aa_bit_stay_quiet() {
    let q = question(NAME, 33, "SRV", querier());
    assert!(aa_findings(vec![row(SERVICE, &q)], &queries(&q, 4, 0)).is_empty());
}

#[test]
fn a_response_with_the_aa_bit_raises_nothing() {
    // Responses set AA as they must (§18.4); even one that wrongly
    // carried a question is no query.
    let q = question(NAME, 33, "SRV", querier());
    let events = vec![packet(QR | AA, vec![q.clone()])];
    assert!(aa_findings(vec![row(SERVICE, &q)], &events).is_empty());
}

#[test]
fn one_shot_queriers_and_probes_are_held_to_it() {
    // §18.4 binds every query message.
    let one_shot = question(NAME, 33, "SRV", "192.168.1.70:49152".parse().unwrap());
    let found = aa_findings(vec![row(SERVICE, &one_shot)], &queries(&one_shot, 1, 1));
    assert_eq!(found.len(), 1, "{found:#?}");

    let q = question(NAME, 255, "ANY", querier());
    let mut probe = packet(AA, vec![q.clone()]);
    let mut proposed = rec(NAME, 33, "SRV", "0 0 80 host.local.", 120, false);
    proposed.source = querier();
    probe.query_authority = vec![proposed];
    assert!(probe.is_probe());
    let found = aa_findings(vec![row(SERVICE, &q)], &[probe]);
    assert_eq!(found.len(), 1, "{found:#?}");
}

#[test]
fn every_question_of_the_query_is_marked() {
    let srv = question(NAME, 33, "SRV", querier());
    let txt = question(NAME, 16, "TXT", querier());
    let events = vec![packet(AA, vec![srv.clone(), txt.clone()])];
    let found = aa_findings(vec![row(SERVICE, &srv), row(SERVICE, &txt)], &events);
    let mut types: Vec<_> = found.iter().filter_map(|f| f.rtype).collect();
    types.sort_unstable();
    assert_eq!(types, vec![16, 33], "{found:#?}");
}

#[test]
fn a_question_twice_in_one_query_counts_once() {
    let q = question(NAME, 33, "SRV", querier());
    let events = vec![packet(AA, vec![q.clone(), q.clone()])];
    let found = aa_findings(vec![row(SERVICE, &q)], &events);
    assert!(
        found[0].message.starts_with("AA bit set in 1 of 1 query "),
        "{}",
        found[0].message
    );
}

#[test]
fn names_fold_ascii_case_only() {
    // RFC 6762 §16: the queries asked in upper case land on the row.
    let row_q = question(NAME, 33, "SRV", querier());
    let upper = question(&NAME.to_ascii_uppercase(), 33, "SRV", querier());
    let found = aa_findings(vec![row(SERVICE, &row_q)], &queries(&upper, 2, 2));
    assert_eq!(found.len(), 1, "{found:#?}");

    // `É` and `é` are two names: no finding on the other row.
    let accented = question("Écran._http._tcp.local.", 33, "SRV", querier());
    let other = question("écran._http._tcp.local.", 33, "SRV", querier());
    let found = aa_findings(vec![row(SERVICE, &accented)], &queries(&other, 2, 2));
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn other_queriers_are_not_blamed() {
    let q = question(NAME, 33, "SRV", querier());
    let other = question(NAME, 33, "SRV", "192.168.1.71:5353".parse().unwrap());
    let found = aa_findings(vec![row(SERVICE, &q)], &queries(&other, 2, 2));
    assert!(found.is_empty(), "{found:#?}");
}

#[test]
fn an_enumeration_question_is_flagged_there() {
    let q = question(ENUM_SERVICE, 12, "PTR", querier());
    let found = aa_findings(vec![row(ENUMERATION_SERVICE, &q)], &queries(&q, 1, 1));
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(found[0].service, ENUMERATION_SERVICE);
}

/// `q` as received on `iface`.
fn on_link(q: &RawRecord, iface: &str, ifindex: u32) -> RawRecord {
    let mut q = q.clone();
    q.iface = iface.to_string();
    q.ifindex = ifindex;
    q
}

/// A sighting row for `q`, labelled with its link.
fn sighting(q: &RawRecord) -> QuestionView<'_> {
    QuestionView {
        source_label: q.source_label(),
        ..row(SERVICE, q)
    }
}

/// A sighting row names its link: it counts that link's queries only,
/// while a Questions row (no link) counts every link's.
#[test]
fn a_link_labelled_row_counts_its_own_link() {
    let q = question(NAME, 33, "SRV", querier());
    let eth0 = on_link(&q, "eth0", 2);
    let wlan0 = on_link(&q, "wlan0", 3);
    let mut events = queries(&eth0, 2, 2);
    events.extend(queries(&wlan0, 3, 0));
    let found = aa_findings(
        vec![sighting(&eth0), sighting(&wlan0), row(SERVICE, &q)],
        &events,
    );
    let mut got: Vec<_> = found
        .iter()
        .map(|a| (a.source.clone().unwrap(), a.message.clone()))
        .collect();
    got.sort();
    assert_eq!(
        got,
        vec![
            (
                "192.168.1.70:5353".to_string(),
                "AA bit set in 2 of 5 queries (must be zero in queries)".to_string()
            ),
            (
                "192.168.1.70:5353@eth0".to_string(),
                "AA bit set in 2 of 2 queries (must be zero in queries)".to_string()
            ),
        ],
        "{found:#?}"
    );
}

/// RFC 6762 §18.3 (#427): an AA-set query with a non-zero OPCODE (here
/// UPDATE) is ignored, not judged as a query.
#[test]
fn a_nonzero_opcode_message_raises_no_aa_finding() {
    let q = question(NAME, 33, "SRV", querier());
    let update = 5 << 3;
    let events: Vec<_> = (0..3)
        .map(|_| packet(AA | update, vec![q.clone()]))
        .collect();
    assert!(aa_findings(vec![row(SERVICE, &q)], &events).is_empty());
    // One standard query among them is judged alone.
    let mut events = events;
    events.push(packet(AA, vec![q.clone()]));
    let found = aa_findings(vec![row(SERVICE, &q)], &events);
    assert_eq!(found.len(), 1, "{found:#?}");
    assert_eq!(
        found[0].message,
        "AA bit set in 1 of 1 query (must be zero in queries)"
    );
}
