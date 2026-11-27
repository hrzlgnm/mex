// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Query section checks over the retained packets: records a querier
//! puts where responders never look (RFC 6762 §7.1, #424).

use super::rate::{record_content, QuestionTally};
use super::*;
use crate::browse::Event;

/// One question's queries carrying answers to it in their Additional
/// section.
#[derive(Default)]
struct Misplaced {
    /// Query packets carrying the question and at least one such answer.
    queries: usize,
    /// The distinct misplaced records, `name TYPE`, in arrival order.
    records: Vec<String>,
    /// Their identities: the name folded ASCII-only (RFC 6762 §16), the
    /// type and the content as `record_content` compares it, so two
    /// addresses of one name stay two and a target's case doesn't split one.
    seen: HashSet<(String, u16, String)>,
}

/// Whether `r` answers the question `q`: the same name (ASCII case
/// folded) and type, or any type for an ANY question. Only such a record
/// is a known answer (RFC 6762 §7.1); any other suppresses nothing in
/// either section.
fn answers(r: &RawRecord, q: &RawRecord) -> bool {
    r.name.eq_ignore_ascii_case(&q.name) && (q.rtype == 255 || r.rtype == q.rtype)
}

/// `misplaced-known-answer` (#424): a querier listing the answers it
/// already knows in its query's Additional section instead of the
/// Answer section (RFC 6762 §7.1) suppresses nothing, so every responder
/// answers anyway and each answer renews every cache on the link. EDNS0
/// OPT never counts (the packet walk drops it), and probes are left out:
/// their records sit in the Authority section. A record counts only for
/// the question it answers, so a query asking two things marks only the
/// rows its misplaced records answer. Each finding goes on the querier's
/// Questions row of every service the question files under, naming the
/// misplaced record and counting the queries per link as `QuestionTally`
/// says.
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
        tally.add_packet(ev, |m, q| {
            let mut carried = false;
            for r in ev.query_additional.iter().filter(|r| answers(r, q)) {
                carried = true;
                let identity = (r.name.to_ascii_lowercase(), r.rtype, record_content(r));
                if m.seen.insert(identity) {
                    m.records.push(format!("{} {}", r.name, r.rtype_str));
                }
            }
            m.queries += usize::from(carried);
        });
    }
    for q in questions {
        let Some(m) = tally.get(q) else {
            continue;
        };
        let records = match m.records.as_slice() {
            [one] => format!("known answer {one}"),
            [first, rest @ ..] => format!("known answers {first} and {} more", rest.len()),
            // The question rode in such a packet, but nothing there
            // answered it.
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
