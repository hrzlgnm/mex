// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Query section checks over the retained packets: records a querier
//! puts where responders never look (RFC 6762 §7.1, #424).

use super::rate::QuestionTally;
use super::*;
use crate::browse::Event;

/// One question's queries carrying records in their Additional section.
#[derive(Default)]
struct Misplaced {
    /// Query packets carrying the question and at least one such record.
    queries: usize,
    /// The distinct misplaced records, `name TYPE`, in arrival order.
    records: Vec<String>,
    /// Their identities: the name folded ASCII-only (RFC 6762 §16) and
    /// the type.
    seen: HashSet<(String, u16)>,
}

/// `misplaced-known-answer` (#424): a querier listing the answers it
/// already knows in its query's Additional section instead of the
/// Answer section (RFC 6762 §7.1) suppresses nothing, so every responder
/// answers anyway and each answer renews every cache on the link. EDNS0
/// OPT never counts (the packet walk drops it), and probes are left out:
/// their records sit in the Authority section. Each finding goes on the
/// querier's Questions row of every service the question files under,
/// naming the misplaced record and counting the queries per link as
/// `QuestionTally` says.
pub(super) fn check_misplaced_known_answers(
    questions: &[QuestionView<'_>],
    events: &[Event],
    out: &mut Vec<Anomaly>,
) {
    let carries_misplaced = |ev: &&Event| !ev.query_additional.is_empty() && !ev.is_probe();
    if questions.is_empty() || !events.iter().any(|ev| carries_misplaced(&ev)) {
        return;
    }
    let mut tally = QuestionTally::<Misplaced>::new();
    for ev in events.iter().filter(carries_misplaced) {
        tally.add_packet(ev, |m| {
            m.queries += 1;
            for r in &ev.query_additional {
                if m.seen.insert((r.name.to_ascii_lowercase(), r.rtype)) {
                    m.records.push(format!("{} {}", r.name, r.rtype_str));
                }
            }
        });
    }
    for q in questions {
        let Some(m) = tally.get(q) else {
            continue;
        };
        let records = match m.records.as_slice() {
            [one] => format!("known answer {one}"),
            [first, rest @ ..] => format!("known answers {first} and {} more", rest.len()),
            [] => continue,
        };
        let noun = if m.queries == 1 { "query" } else { "queries" };
        out.push(Anomaly {
            kind: AnomalyKind::MisplacedKnownAnswer,
            severity: Severity::Warning,
            service: q.service.clone(),
            record_name: Some(q.name.to_string()),
            rtype: Some(q.rtype),
            rtype_str: Some(q.rtype_str.to_string()),
            rdata: None,
            source: Some(q.source_label.clone()),
            message: format!(
                "{records} in the Additional section of {} {noun}; \
                 responders suppress only on the Answer section",
                m.queries
            ),
            rfc: "RFC 6762 §7.1",
            requirement: "",
            response: None,
            responders: Vec::new(),
        });
    }
}
