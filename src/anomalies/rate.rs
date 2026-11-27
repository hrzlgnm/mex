// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Rate checks over the retained packets: one source sending the same
//! thing on one link again within a second (questions: RFC 6762 §5.2,
//! #408).

use super::*;
use crate::browse::Event;

/// The RFC floor between two sends of the same thing on one link.
const MIN_GAP: Duration = Duration::from_secs(1);

/// How one identity repeated within the retained packets.
#[derive(Debug, PartialEq)]
pub(super) struct Repeats {
    /// Sends seen, one per packet.
    pub count: usize,
    /// From the first send to the last.
    pub span: Duration,
    /// The shortest gap between two consecutive sends.
    pub min_gap: Duration,
}

impl Repeats {
    /// `asked 27 times in 6 s, as little as 0.2 s apart`.
    pub fn describe(&self, verb: &str) -> String {
        format!(
            "{verb} {} times in {} s, as little as {} s apart",
            self.count,
            fmt_secs(self.span),
            fmt_secs(self.min_gap)
        )
    }
}

/// The repeats of one identity, given each packet's receive time (one
/// per packet: copies inside a packet are one send), or `None` while
/// every gap keeps the one-second floor.
pub(super) fn repeats(mut times: Vec<Instant>) -> Option<Repeats> {
    times.sort();
    let min_gap = times.windows(2).map(|w| w[1] - w[0]).min()?;
    (min_gap < MIN_GAP).then(|| Repeats {
        count: times.len(),
        span: times[times.len() - 1] - times[0],
        min_gap,
    })
}

/// Seconds with at most two decimals, trailing zeros dropped: `1`, `0.25`.
pub(super) fn fmt_secs(d: Duration) -> String {
    let s = format!("{:.2}", d.as_secs_f64());
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Identity of one asking: the name folded ASCII-only (RFC 6762 §16),
/// the type, and the querier as findings name it (address plus link).
type AskingKey = (String, u16, String);

fn asking_key(name: &str, rtype: u16, source_label: String) -> AskingKey {
    (name.to_ascii_lowercase(), rtype, source_label)
}

/// A continuous querier, the only kind RFC 6762 §5.2 binds: it asks
/// from port 5353. Any other port is a one-shot querier (§5.1) or our
/// own inferred send (port 0); unlike `is_one_shot_querier`, which tags
/// only ephemeral ports, this excludes every port but 5353.
fn is_continuous_querier(source: &SocketAddr) -> bool {
    source.port() == 5353
}

/// `query-rate-limit` (#408): a continuous querier asking one question
/// on one link again within a second breaks RFC 6762 §5.2 (the first two
/// queries MUST be at least one second apart). Only the one-second
/// floor is checked; the doubling half needs a longer history than the
/// retained packets hold. Probes (§8.1, 250 ms apart) are exempt. Each
/// finding goes on the querier's Questions row of every service the
/// question files under.
pub(super) fn check_query_rate(
    questions: &[QuestionView<'_>],
    events: &[Event],
    out: &mut Vec<Anomaly>,
) {
    if questions.is_empty() {
        return;
    }
    let mut times: HashMap<AskingKey, Vec<Instant>> = HashMap::new();
    for ev in events.iter().filter(|ev| !ev.is_probe()) {
        let mut in_packet = HashSet::new();
        for q in ev
            .questions
            .iter()
            .filter(|q| is_continuous_querier(&q.source))
        {
            let key = asking_key(&q.name, q.rtype, q.source_label());
            if in_packet.insert(key.clone()) {
                times.entry(key).or_default().push(ev.received_at);
            }
        }
    }
    let mut verdicts: HashMap<AskingKey, Option<Repeats>> = HashMap::new();
    for q in questions
        .iter()
        .filter(|q| is_continuous_querier(&q.source))
    {
        let key = asking_key(q.name, q.rtype, q.source_label.clone());
        let verdict = verdicts
            .entry(key.clone())
            .or_insert_with(|| times.get(&key).and_then(|t| repeats(t.clone())));
        let Some(rep) = verdict else {
            continue;
        };
        out.push(Anomaly {
            kind: AnomalyKind::QueryRateLimit,
            severity: Severity::Warning,
            service: q.service.clone(),
            record_name: Some(q.name.to_string()),
            rtype: Some(q.rtype),
            rtype_str: Some(q.rtype_str.to_string()),
            rdata: None,
            source: Some(q.source_label.clone()),
            message: format!("{} (at least 1 s, then doubling)", rep.describe("asked")),
            rfc: "RFC 6762 §5.2",
            requirement: "MUST",
            response: None,
            responders: Vec::new(),
        });
    }
}
