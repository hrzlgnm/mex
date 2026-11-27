// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Query header checks over the retained packets: header bits a querier
//! must not set (RFC 6762 §18, #423).

use super::rate::{asking_key, AskingKey};
use super::*;
use crate::browse::Event;

/// How often one question went out with the AA bit set.
#[derive(Default)]
struct AaCount {
    /// Query packets carrying the question.
    queries: usize,
    /// Those of them with the AA bit set.
    authoritative: usize,
}

/// `query-aa-bit` (#423): a querier setting the Authoritative Answer bit
/// in a query breaks RFC 6762 §18.4 (MUST be zero in queries; receivers
/// ignore it). Every querier is held to it, one-shot or probing alike.
/// Each finding goes on the querier's Questions row of every service the
/// question files under, with how many of that question's retained
/// queries carried the bit. Questions rows carry no ingress link, so a
/// querier's queries on every link count together there; a sighting row
/// labelled with its link (`address@iface`) counts that link's queries
/// only.
pub(super) fn check_query_aa_bit(
    questions: &[QuestionView<'_>],
    events: &[Event],
    out: &mut Vec<Anomaly>,
) {
    // Nearly every querier keeps AA clear: count nothing until one
    // retained query has it set.
    if questions.is_empty() || !events.iter().any(Event::is_authoritative_query) {
        return;
    }
    // Per querier over every link, and per querier and link label.
    let mut counts: HashMap<AskingKey, AaCount> = HashMap::new();
    let mut per_link: HashMap<(AskingKey, String), AaCount> = HashMap::new();
    for ev in events {
        let aa = ev.is_authoritative_query();
        // A question asked twice in one packet is one query.
        let mut in_packet = HashSet::new();
        for q in &ev.questions {
            let key = asking_key(&q.name, q.rtype, q.source);
            if in_packet.insert(key.clone()) {
                for count in [
                    counts.entry(key.clone()).or_default(),
                    per_link.entry((key, q.source_label())).or_default(),
                ] {
                    count.queries += 1;
                    count.authoritative += usize::from(aa);
                }
            }
        }
    }
    for q in questions {
        let key = asking_key(q.name, q.rtype, q.source);
        // A bare label stands for every link; a link-qualified one for its
        // own link (an IPv6 zone already sits in the address).
        let count = if q.source_label == q.source.to_string() {
            counts.get(&key)
        } else {
            per_link.get(&(key, q.source_label.clone()))
        };
        let Some(count) = count else {
            continue;
        };
        if count.authoritative == 0 {
            continue;
        }
        let noun = if count.queries == 1 {
            "query"
        } else {
            "queries"
        };
        out.push(Anomaly {
            kind: AnomalyKind::QueryAaBit,
            severity: Severity::Warning,
            service: q.service.clone(),
            record_name: Some(q.name.to_string()),
            rtype: Some(q.rtype),
            rtype_str: Some(q.rtype_str.to_string()),
            rdata: None,
            source: Some(q.source_label.clone()),
            message: format!(
                "AA bit set in {} of {} {noun} (must be zero in queries)",
                count.authoritative, count.queries
            ),
            rfc: "RFC 6762 §18.4",
            requirement: "MUST",
            response: None,
            responders: Vec::new(),
        });
    }
}
