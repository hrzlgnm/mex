// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Rate checks over the retained packets: one source sending the same
//! thing on one link again within a second (questions: RFC 6762 §5.2,
//! #408; records: §6, #407).

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
/// Truncated, never rounded up: a 999 ms gap reads `0.99`, not `1`,
/// which would look like it kept the one-second floor.
pub(super) fn fmt_secs(d: Duration) -> String {
    let centis = d.as_millis() / 10;
    let s = format!("{}.{:02}", centis / 100, centis % 100);
    s.trim_end_matches('0').trim_end_matches('.').to_string()
}

/// Identity of one question as a Questions row knows it: the name folded
/// ASCII-only (RFC 6762 §16), the type, and the querier address. Rows
/// carry no ingress link, so links are told apart below it.
type AskingKey = (String, u16, SocketAddr);

/// An ingress link: interface name and index, so two unnamed links stay
/// two.
type Link = (String, u32);

fn asking_key(name: &str, rtype: u16, source: SocketAddr) -> AskingKey {
    (name.to_ascii_lowercase(), rtype, source)
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
    // Each question's askings, per link: one querier asking once on each
    // of two links is not a repeat.
    let mut times: HashMap<AskingKey, HashMap<Link, Vec<Instant>>> = HashMap::new();
    for ev in events.iter().filter(|ev| !ev.is_probe()) {
        let mut in_packet = HashSet::new();
        for q in ev
            .questions
            .iter()
            .filter(|q| is_continuous_querier(&q.source))
        {
            let key = asking_key(&q.name, q.rtype, q.source);
            let link = (q.iface.clone(), q.ifindex);
            if in_packet.insert((key.clone(), link.clone())) {
                times
                    .entry(key)
                    .or_default()
                    .entry(link)
                    .or_default()
                    .push(ev.received_at);
            }
        }
    }
    let mut verdicts: HashMap<AskingKey, Option<Repeats>> = HashMap::new();
    for q in questions
        .iter()
        .filter(|q| is_continuous_querier(&q.source))
    {
        let key = asking_key(q.name, q.rtype, q.source);
        // The row stands for every link the querier asked on: its worst
        // link (the shortest gap) decides.
        let verdict = verdicts.entry(key.clone()).or_insert_with(|| {
            times.get(&key).and_then(|links| {
                links
                    .values()
                    .filter_map(|t| repeats(t.clone()))
                    .min_by_key(|r| r.min_gap)
            })
        });
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

/// Identity of one record transmission: the owner name folded ASCII-only
/// (RFC 6762 §16), the type, the rdata, and the responder as findings
/// name it (address plus link).
type SendKey = (String, u16, String, String);

fn send_key(r: &RawRecord) -> SendKey {
    // A PTR target is a name, and ingest replaces a PTR row whose target
    // differs only in case: a responder varying that case still repeats
    // one record. Other rdata (TXT) is compared exactly, like ingest.
    let rdata = if r.rtype == 12 {
        r.rdata.to_ascii_lowercase()
    } else {
        r.rdata.clone()
    };
    (
        r.name.to_ascii_lowercase(),
        r.rtype,
        rdata,
        r.source_label(),
    )
}

/// A probe query seen on a link (RFC 6762 §8.1): the owner names it asks
/// about or proposes records for, folded ASCII-only.
struct Probe {
    at: Instant,
    names: HashSet<String>,
    iface: String,
    ifindex: u32,
}

/// Multicast record sends in the retained packets, indexed once per
/// analysis so every row is checked against them cheaply (#407).
pub(super) struct MulticastIndex<'a> {
    /// The retained packets, in arrival order (one listener thread
    /// stamps and queues them).
    events: &'a [Event],
    /// Each identity's sends: receive time and packet index, one per
    /// packet (a record in two sections of one response is one send).
    sends: HashMap<SendKey, Vec<(Instant, usize)>>,
    probes: Vec<Probe>,
}

impl<'a> MulticastIndex<'a> {
    pub fn new(events: &'a [Event]) -> Self {
        let mut sends: HashMap<SendKey, Vec<(Instant, usize)>> = HashMap::new();
        let mut probes = Vec::new();
        for (i, ev) in events.iter().enumerate() {
            if ev.is_probe() {
                // Every record of a packet shares its ingress link.
                let first = &ev.query_authority[0];
                probes.push(Probe {
                    at: ev.received_at,
                    names: ev
                        .questions
                        .iter()
                        .chain(&ev.query_authority)
                        .map(|r| r.name.to_ascii_lowercase())
                        .collect(),
                    iface: first.iface.clone(),
                    ifindex: first.ifindex,
                });
            }
            let mut in_packet = HashSet::new();
            // Only multicast copies count, and a goodbye is a withdrawal,
            // not a repeat.
            for r in ev
                .answers
                .iter()
                .filter(|r| r.dst_is_multicast && r.ttl > 0)
            {
                let key = send_key(r);
                if in_packet.insert(key.clone()) {
                    sends.entry(key).or_default().push((ev.received_at, i));
                }
            }
        }
        Self {
            events,
            sends,
            probes,
        }
    }

    /// Whether a probe for `rec`'s owner name arrived on its link in the
    /// second before `at`: answering it is conflict defense, the one
    /// exception RFC 6762 §6 allows.
    fn probed(&self, rec: &RawRecord, at: Instant) -> bool {
        let name = rec.name.to_ascii_lowercase();
        self.probes.iter().any(|p| {
            p.at <= at
                && at - p.at <= MIN_GAP
                && p.iface == rec.iface
                && p.ifindex == rec.ifindex
                && p.names.contains(&name)
        })
    }

    /// The question a copy most likely answered (mDNS responses carry no
    /// question section, so timing is all there is): the latest query
    /// from another source on the copy's link, up to a second before it,
    /// asking a name present in that response packet. `querier asking
    /// name TYPE`.
    fn trigger(&self, rec: &RawRecord, at: Instant, packet: usize) -> Option<String> {
        let names: HashSet<String> = self.events[packet]
            .answers
            .iter()
            .map(|r| r.name.to_ascii_lowercase())
            .collect();
        // Packets arrive in order: walk back only through the second
        // before the copy, not the whole retained buffer.
        self.events[..packet]
            .iter()
            .rev()
            .take_while(|ev| at.saturating_duration_since(ev.received_at) <= MIN_GAP)
            .filter(|ev| ev.source != rec.source && !ev.is_probe())
            .find_map(|ev| {
                ev.questions
                    .iter()
                    .find(|q| {
                        q.iface == rec.iface
                            && q.ifindex == rec.ifindex
                            && names.contains(&q.name.to_ascii_lowercase())
                    })
                    .map(|q| format!("{} asking {} {}", q.source_label(), q.name, q.rtype_str))
            })
    }

    /// `multicast-rate-limit` (#407): a responder multicasting one record
    /// on one link again within a second breaks RFC 6762 §6 (MUST NOT,
    /// except answering a probe). Each repeat renews the cached row, so
    /// its TTL never counts down and its refresh never fires. The finding
    /// takes `rec`'s full identity, so it sits on that Answers row of
    /// `service`, and names what the repeats most likely answered.
    pub fn check(&self, service: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
        let Some(copies) = self.sends.get(&send_key(rec)) else {
            return;
        };
        let kept: Vec<(Instant, usize)> = copies
            .iter()
            .copied()
            .filter(|(at, _)| !self.probed(rec, *at))
            .collect();
        let Some(rep) = repeats(kept.iter().map(|(at, _)| *at).collect()) else {
            return;
        };
        let trigger = kept
            .iter()
            .rev()
            .find_map(|(at, packet)| self.trigger(rec, *at, *packet))
            .map(|t| format!(", answering {t}"))
            .unwrap_or_default();
        out.push(Anomaly {
            kind: AnomalyKind::MulticastRateLimit,
            severity: Severity::Warning,
            service: service.to_string(),
            record_name: Some(rec.name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rec.rdata.clone()),
            source: Some(rec.source_label()),
            message: format!("{}{trigger}", rep.describe("multicast")),
            rfc: "RFC 6762 §6",
            requirement: "MUST NOT",
            response: None,
            responders: Vec::new(),
        });
    }
}
