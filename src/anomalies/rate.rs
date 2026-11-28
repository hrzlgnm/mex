// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Rate checks over the retained packets: one source sending the same
//! thing on one link again within a second (questions: RFC 6762 §5.2,
//! #408; records: §6, #407).

use std::collections::{BTreeMap, BTreeSet};
use std::net::IpAddr;

use super::*;
use crate::browse::{Event, OwnSend};

/// The RFC floor between two sends of the same thing on one link.
pub(crate) const MIN_GAP: Duration = Duration::from_secs(1);

/// The reply delay RFC 6762 §6 lets a responder add (a random 20–120 ms),
/// used as a tolerance when judging its answers (#442): queries this close
/// together are one round, and answers to queries a second apart may land
/// this much closer than a second.
const REPLY_DELAY: Duration = Duration::from_millis(120);

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
pub(super) fn repeats(times: Vec<Instant>) -> Option<Repeats> {
    repeats_except(times.into_iter().map(|at| (at, false)).collect())
}

/// `repeats`, where a send flagged `true` is allowed to come early (an
/// answer to a probe, RFC 6762 §6): the gap ending in it is not judged,
/// but it still counts as a send, and the next gap starts from it.
fn repeats_except(mut sends: Vec<(Instant, bool)>) -> Option<Repeats> {
    sends.sort();
    let min_gap = sends
        .windows(2)
        .filter(|w| !w[1].1)
        .map(|w| w[1].0 - w[0].0)
        .min()?;
    (min_gap < MIN_GAP).then(|| Repeats {
        count: sends.len(),
        span: sends[sends.len() - 1].0 - sends[0].0,
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

/// A tally per question over the retained queries, for the findings that
/// count a querier's queries (#423, #424): per querier over every link,
/// and per querier and link label. Questions rows carry no ingress link,
/// so they read the first; a sighting row labelled with its link
/// (`address@iface`) reads only its own link (an IPv6 zone already sits
/// in the address).
pub(super) struct QuestionTally<T> {
    all: HashMap<AskingKey, T>,
    per_link: HashMap<(AskingKey, String), T>,
}

impl<T: Default> QuestionTally<T> {
    pub(super) fn new() -> Self {
        Self {
            all: HashMap::new(),
            per_link: HashMap::new(),
        }
    }

    /// Apply `add` once per question of `ev`, with that question: a
    /// question asked twice in one packet is one query.
    pub(super) fn add_packet(&mut self, ev: &Event, add: impl Fn(&mut T, &RawRecord)) {
        let mut in_packet = HashSet::new();
        for q in &ev.questions {
            let key = asking_key(&q.name, q.rtype, q.source);
            if in_packet.insert(key.clone()) {
                add(self.all.entry(key.clone()).or_default(), q);
                add(self.per_link.entry((key, q.source_label())).or_default(), q);
            }
        }
    }

    /// The tally for the row `q`.
    pub(super) fn get(&self, q: &QuestionView<'_>) -> Option<&T> {
        let key = asking_key(q.name, q.rtype, q.source);
        if q.source_label == q.source.to_string() {
            self.all.get(&key)
        } else {
            self.per_link.get(&(key, q.source_label.clone()))
        }
    }
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
/// (RFC 6762 §16), the type, the content, the responder address, and its
/// link (interface name and index, so two unnamed links stay two).
type SendKey = (String, u16, String, SocketAddr, Link);

/// A record's content as an identity: one record sent twice, or listed
/// twice, compares equal.
pub(super) fn record_content(r: &RawRecord) -> String {
    match r.rdata_digest {
        // Out-of-scope rdata shows only `rdlength=<n>`: its digest tells
        // a repeat from new content of one length (an SOA serial bump).
        Some(digest) => format!("#{digest:016x}"),
        // Name-valued rdata (PTR, CNAME, NS targets, the SRV target, the
        // NSEC next name) folds ASCII case like any name, so a responder
        // varying that case still repeats one record. The NSEC bitmap's
        // mnemonics stay distinct when folded. Other rdata (TXT) compares
        // exactly.
        None if matches!(r.rtype, 2 | 5 | 12 | 33 | 47) => r.rdata.to_ascii_lowercase(),
        None => r.rdata.clone(),
    }
}

/// The question of a packet a copy of `rec` most likely answered: one
/// asking `rec`'s own name and type (or ANY), else the first asking any
/// name of the copy's packet (`names`, as `name_key`s). A packed query
/// (#430) asks SRV and TXT, or A and AAAA, of one name together, so the
/// name alone can pick the wrong type.
fn pick_question<'q, Q>(
    questions: &'q [Q],
    rec: &RawRecord,
    names: &HashSet<String>,
    ask: impl Fn(&Q) -> (&str, u16),
) -> Option<&'q Q> {
    let own = name_key(&rec.name);
    questions
        .iter()
        .find(|q| {
            let (name, rtype) = ask(q);
            (rtype == rec.rtype || rtype == 255) && name_key(name) == own
        })
        .or_else(|| {
            questions
                .iter()
                .find(|q| names.contains(&name_key(ask(q).0)))
        })
}

fn send_key(r: &RawRecord) -> SendKey {
    (
        r.name.to_ascii_lowercase(),
        r.rtype,
        record_content(r),
        r.source,
        (r.iface.clone(), r.ifindex),
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

/// One device asking one question on one link: the device identity
/// (`DeviceLabel::id`), the question name folded ASCII-only, its type,
/// and the link.
type DeviceAskingKey = (String, String, u16, Link);

/// Multicast record sends in the retained packets, indexed once per
/// analysis so every row is checked against them cheaply (#407).
/// One identity's copies, grouped once per analysis (#442).
struct Grouped<'a> {
    /// The record the copies carry.
    rec: &'a RawRecord,
    /// Which copies answer a probe.
    probed: Vec<bool>,
    bursts: Bursts,
}

/// A record's copies grouped by the query they answered (#442).
#[derive(Default)]
struct Bursts {
    /// Most copies sent for one query.
    per_query: usize,
    /// Longest time from the first to the last copy for one query.
    span: Duration,
    /// When each query answered with more than one copy was asked.
    queries: HashSet<Instant>,
    /// The shortest repeat within a second that isn't part of a burst
    /// (it answers another query, or none), measured from the first copy
    /// of the burst before it, if any.
    unexplained: Option<Duration>,
}

pub(super) struct MulticastIndex<'a> {
    /// The retained packets, in arrival order (one listener thread
    /// stamps and queues them).
    events: &'a [Event],
    /// Our own sent query copies (#431), in send order, on the clock of
    /// `events`: a copy may answer one of them.
    own_sends: &'a [OwnSend],
    /// Each identity's sends: receive time and packet index, one per
    /// packet (a record in two sections of one response is one send).
    sends: HashMap<SendKey, Vec<(Instant, usize)>>,
    probes: Vec<Probe>,
    /// Each identity sent more than once, grouped once per analysis
    /// (#442): its record, which copies answer a probe, and its bursts.
    /// A single copy can't repeat, so it's left out.
    grouped: HashMap<SendKey, Grouped<'a>>,
    /// Device names behind source addresses, for naming a trigger.
    device_names: &'a HashMap<IpAddr, DeviceLabel>,
    /// Each device's display name, by identity: an exact match's name
    /// beats an inferred (`~`) one, so the name doesn't depend on which
    /// address asked last.
    device_display: HashMap<&'a str, &'a str>,
    /// Each known device's querier labels per question and link, sorted:
    /// one device asking over IPv4 and IPv6 names both addresses.
    device_askers: HashMap<DeviceAskingKey, BTreeSet<String>>,
}

/// One display name per device identity: an exact match's name over an
/// inferred one (`~`-prefixed), then the alphabetically first.
fn display_names(devices: &HashMap<IpAddr, DeviceLabel>) -> HashMap<&str, &str> {
    let mut out: HashMap<&str, &str> = HashMap::new();
    for d in devices.values() {
        out.entry(d.id.as_str())
            .and_modify(|cur| {
                if (d.name.starts_with('~'), d.name.as_str()) < (cur.starts_with('~'), *cur) {
                    *cur = d.name.as_str();
                }
            })
            .or_insert(d.name.as_str());
    }
    out
}

impl<'a> MulticastIndex<'a> {
    pub fn new(
        events: &'a [Event],
        own_sends: &'a [OwnSend],
        device_names: &'a HashMap<IpAddr, DeviceLabel>,
    ) -> Self {
        let mut sends: HashMap<SendKey, Vec<(Instant, usize)>> = HashMap::new();
        // One record per identity, for grouping its copies below.
        let mut records: HashMap<SendKey, &'a RawRecord> = HashMap::new();
        let mut probes = Vec::new();
        let mut device_askers: HashMap<DeviceAskingKey, BTreeSet<String>> = HashMap::new();
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
            } else {
                for q in &ev.questions {
                    if let Some(device) = device_names.get(&q.source.ip()) {
                        device_askers
                            .entry((
                                device.id.clone(),
                                q.name.to_ascii_lowercase(),
                                q.rtype,
                                (q.iface.clone(), q.ifindex),
                            ))
                            .or_default()
                            .insert(q.source_label());
                    }
                }
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
                    records.entry(key.clone()).or_insert(r);
                    sends.entry(key).or_default().push((ev.received_at, i));
                }
            }
        }
        let mut index = Self {
            events,
            own_sends,
            sends,
            probes,
            grouped: HashMap::new(),
            device_display: display_names(device_names),
            device_names,
            device_askers,
        };
        // Each copy's trigger is found once here, not again for every row
        // that shows the record and for the responder findings.
        let grouped = records
            .into_iter()
            .filter_map(|(key, rec)| {
                let copies = index.sends.get(&key)?;
                if copies.len() < 2 {
                    return None;
                }
                let probed = index.probed_copies(rec, copies);
                let bursts = index.bursts(rec, copies, &probed);
                Some((
                    key,
                    Grouped {
                        rec,
                        probed,
                        bursts,
                    },
                ))
            })
            .collect();
        index.grouped = grouped;
        index
    }

    /// Whether the copy at `at` answers a probe: one for `rec`'s owner
    /// name arrived on its link in the second before, and after the
    /// previous copy (`since`), which would otherwise have answered it.
    /// Answering a probe is conflict defense, the one exception RFC 6762
    /// §6 allows.
    fn probed(&self, rec: &RawRecord, at: Instant, since: Option<Instant>) -> bool {
        let name = rec.name.to_ascii_lowercase();
        self.probes.iter().any(|p| {
            p.at <= at
                && at - p.at <= MIN_GAP
                && since.is_none_or(|prev| p.at > prev)
                && p.iface == rec.iface
                && p.ifindex == rec.ifindex
                && p.names.contains(&name)
        })
    }

    /// The question a copy most likely answered (mDNS responses carry no
    /// question section, so timing is all there is): a query from
    /// another source on the copy's link, up to a second before it,
    /// asking a name present in that response packet. `querier asking
    /// name TYPE`.
    ///
    /// A querier often sends one query over IPv4 and IPv6 within a
    /// millisecond, in either order, so "the latest" alternates between
    /// its two addresses. To keep the text stable: a querier that
    /// resolves to a device is named as that device, with every address
    /// it asked this question from on the link; otherwise the latest
    /// query of the copy's own address family wins, then the latest of
    /// any family.
    ///
    /// Our own query (#431) wins when it is the latest asking: it reads
    /// `mex (this host) asking name TYPE`, never through the address
    /// book, so this host's own announced name doesn't stand in for mex.
    fn trigger(&self, rec: &RawRecord, at: Instant, packet: usize) -> Option<String> {
        let names = self.packet_names(packet);
        let foreign = self.foreign_askings(rec, at, packet, &names);
        if let Some((sent_at, (name, rtype))) = self.own_askings(rec, at, &names).next() {
            if foreign
                .first()
                .is_none_or(|(asked_at, _)| sent_at > *asked_at)
            {
                return Some(format!(
                    "mex (this host) asking {}. {}",
                    name.trim_end_matches('.'),
                    crate::browse::rtype_label(*rtype)
                ));
            }
        }
        let askings: Vec<&RawRecord> = foreign.into_iter().map(|(_, q)| q).collect();
        let device = askings.iter().find_map(|q| {
            let device = self.device_names.get(&q.source.ip())?;
            let key = (
                device.id.clone(),
                q.name.to_ascii_lowercase(),
                q.rtype,
                (q.iface.clone(), q.ifindex),
            );
            let labels = self.device_askers.get(&key)?;
            let name = self.device_display.get(device.id.as_str())?;
            Some((q, name, labels))
        });
        if let Some((q, device, labels)) = device {
            let labels: Vec<&str> = labels.iter().map(String::as_str).collect();
            return Some(format!(
                "{device} ({}) asking {} {}",
                labels.join(", "),
                q.name,
                q.rtype_str
            ));
        }
        let q = askings
            .iter()
            .find(|q| q.source.is_ipv4() == rec.source.is_ipv4())
            .or(askings.first())?;
        Some(format!(
            "{} asking {} {}",
            q.source_label(),
            q.name,
            q.rtype_str
        ))
    }

    /// When the query a copy at `at` most likely answered was asked: the
    /// latest asking among other queriers' questions and our own sends,
    /// as the trigger picks them. `None` for an unsolicited copy.
    fn trigger_at(&self, rec: &RawRecord, at: Instant, packet: usize) -> Option<Instant> {
        let names = self.packet_names(packet);
        let foreign = self
            .foreign_askings(rec, at, packet, &names)
            .first()
            .map(|(t, _)| *t);
        let own = self.own_askings(rec, at, &names).next().map(|(t, _)| t);
        foreign.max(own)
    }

    /// A record's copies (`copies`, in arrival order, `probed` marking
    /// probe answers) split by the query they answered (#442). Copies in
    /// a row that answer one query are one burst: the responder sent its
    /// answer several times for one question. A repeat within a second
    /// that isn't part of a burst (a new query's answer, or unsolicited)
    /// is `unexplained`.
    fn bursts(&self, rec: &RawRecord, copies: &[(Instant, usize)], probed: &[bool]) -> Bursts {
        let triggers: Vec<Option<Instant>> = copies
            .iter()
            .map(|(at, packet)| self.trigger_at(rec, *at, *packet))
            .collect();
        // Two neighbouring copies answer one query round: both judged, and
        // their triggers no further apart than a reply delay (a querier
        // sending several questions in packets a few ms apart is one round).
        let same_query = |k: usize| {
            !probed[k]
                && !probed[k - 1]
                && match (triggers[k], triggers[k - 1]) {
                    (Some(a), Some(b)) => a.max(b) - a.min(b) <= REPLY_DELAY,
                    _ => false,
                }
        };
        let mut b = Bursts::default();
        let mut start = 0;
        for k in 1..=copies.len() {
            if k < copies.len() && same_query(k) {
                continue;
            }
            let n = k - start;
            if n > 1 {
                b.per_query = b.per_query.max(n);
                b.span = b.span.max(copies[k - 1].0 - copies[start].0);
                b.queries.extend(triggers[start]);
            }
            start = k;
        }
        // A burst is one answer sent several times: the next send is
        // judged from the burst's first copy, so a responder answering two
        // queries a second apart isn't flagged again for its own
        // duplicates, which the copies-per-query count already reports.
        // Where each round's copies start (a round of one copy included).
        let starts: Vec<usize> = (0..copies.len())
            .filter(|&k| k == 0 || !same_query(k))
            .collect();
        // Answers to queries a second apart may land a reply delay closer;
        // a probe answer may come early (§6).
        b.unexplained = starts
            .windows(2)
            .filter(|w| !probed[w[1]])
            .map(|w| copies[w[1]].0 - copies[w[0]].0)
            .filter(|gap| *gap < MIN_GAP - REPLY_DELAY)
            .min();
        b
    }

    /// `multicast-rate-limit` per responder (#442): a responder whose
    /// records repeat within a second only because it sends its answer
    /// several times per query gets one finding, on its host header (or
    /// `(unattributed)` when it heads no host in `hosts`), instead of one
    /// per record row (`check` stays quiet for those rows). The message
    /// says how many copies per query and within how long.
    pub fn check_bursts(&self, hosts: &HashSet<&str>, out: &mut Vec<Anomaly>) {
        #[derive(Default)]
        struct Responder {
            name: String,
            sources: BTreeSet<String>,
            per_query: usize,
            span: Duration,
            queries: HashSet<Instant>,
            rows: usize,
        }
        // By owner (host header) and responder name, sorted for a stable list.
        let mut responders: BTreeMap<(String, String), Responder> = BTreeMap::new();
        for Grouped { rec, bursts: b, .. } in self.grouped.values() {
            if b.per_query < 2 || b.unexplained.is_some() {
                continue;
            }
            let device = self.device_names.get(&rec.source.ip());
            let owner = match device {
                Some(d) if hosts.contains(d.id.as_str()) => d.id.clone(),
                _ => UNATTRIBUTED_SERVICE.to_string(),
            };
            let who = device
                .and_then(|d| {
                    self.device_display
                        .get(d.id.as_str())
                        .map(|n| n.to_string())
                })
                .unwrap_or_else(|| rec.source.ip().to_string());
            let r = responders.entry((owner, who.clone())).or_default();
            r.name = who;
            r.sources.insert(rec.source_label());
            r.per_query = r.per_query.max(b.per_query);
            r.span = r.span.max(b.span);
            r.queries.extend(b.queries.iter().copied());
            r.rows += 1;
        }
        for ((owner, _), r) in responders {
            let sources: Vec<&str> = r.sources.iter().map(String::as_str).collect();
            let noun = if r.queries.len() == 1 {
                "query"
            } else {
                "queries"
            };
            let rows = if r.rows == 1 { "record" } else { "records" };
            out.push(Anomaly {
                kind: AnomalyKind::MulticastRateLimit,
                severity: Severity::Warning,
                service: owner,
                record_name: None,
                rtype: None,
                rtype_str: None,
                rdata: None,
                source: Some(sources.join(", ")),
                message: format!(
                    "{} ({}) sends its answers up to {} times per query, within {} ms \
                     ({} {noun}, {} {rows})",
                    r.name,
                    sources.join(", "),
                    r.per_query,
                    r.span.as_millis(),
                    r.queries.len(),
                    r.rows
                ),
                rfc: "RFC 6762 §6",
                requirement: "MUST NOT",
                response: None,
                responders: Vec::new(),
            });
        }
    }

    /// Whether each copy answers a probe (`probed`): copies are in arrival
    /// order, so each one's previous copy bounds which probes it can
    /// answer.
    fn probed_copies(&self, rec: &RawRecord, copies: &[(Instant, usize)]) -> Vec<bool> {
        copies
            .iter()
            .enumerate()
            .map(|(i, (at, _))| {
                let since = i.checked_sub(1).map(|prev| copies[prev].0);
                self.probed(rec, *at, since)
            })
            .collect()
    }

    /// Other queriers' questions a copy at `at` may answer, latest first:
    /// asked on the copy's link in the second before it, naming one of its
    /// packet's `names`. Packets arrive in order, so only the second
    /// before the copy is walked, not the whole retained buffer.
    fn foreign_askings(
        &self,
        rec: &RawRecord,
        at: Instant,
        packet: usize,
        names: &HashSet<String>,
    ) -> Vec<(Instant, &RawRecord)> {
        self.events[..packet]
            .iter()
            .rev()
            .take_while(|ev| at.saturating_duration_since(ev.received_at) <= MIN_GAP)
            .filter(|ev| ev.source != rec.source && !ev.is_probe())
            .filter_map(|ev| {
                let on_link: Vec<&RawRecord> = ev
                    .questions
                    .iter()
                    .filter(|q| q.iface == rec.iface && q.ifindex == rec.ifindex)
                    .collect();
                pick_question(&on_link, rec, names, |q| (q.name.as_str(), q.rtype))
                    .map(|q| (ev.received_at, *q))
            })
            .collect()
    }

    /// The owner names of a response packet's records, as `name_key`
    /// keys: the names a question must ask to have triggered it.
    fn packet_names(&self, packet: usize) -> HashSet<String> {
        self.events[packet]
            .answers
            .iter()
            .map(|r| name_key(&r.name))
            .collect()
    }

    /// Our own sends a copy at `at` may answer, latest first: sent on
    /// the copy's link (interface name and index, as for other queriers;
    /// both families count) in the second before it,
    /// asking one of its packet's `names`. Each with the question asked.
    fn own_askings<'s>(
        &'s self,
        rec: &'s RawRecord,
        at: Instant,
        names: &'s HashSet<String>,
    ) -> impl Iterator<Item = (Instant, &'s (String, u16))> + 's {
        // In send order: start at the last send at or before `at`, so the
        // walk covers only the second before it.
        let end = self.own_sends.partition_point(|s| s.sent_at <= at);
        self.own_sends[..end]
            .iter()
            .rev()
            .take_while(move |s| at - s.sent_at <= MIN_GAP)
            .filter(move |s| s.iface == rec.iface && s.ifindex == rec.ifindex)
            .filter_map(move |s| {
                pick_question(&s.questions, rec, names, |(name, rtype)| (name, *rtype))
                    .map(|q| (s.sent_at, q))
            })
    }

    /// `multicast-rate-limit` (#407): a responder multicasting one record
    /// on one link again within a second breaks RFC 6762 §6 (MUST NOT,
    /// except answering a probe). Each repeat renews the cached row, so
    /// its TTL never counts down and its refresh never fires. The finding
    /// takes `rec`'s full identity, so it sits on that Answers row of
    /// `service`, and names what the repeats most likely answered.
    pub fn check(&self, service: &str, rec: &RawRecord, out: &mut Vec<Anomaly>) {
        // Sent once (or never): nothing repeats.
        let key = send_key(rec);
        let (Some(copies), Some(Grouped { probed, bursts, .. })) =
            (self.sends.get(&key), self.grouped.get(&key))
        else {
            return;
        };
        // A probe answer may come early, but it is still a multicast:
        // the next copy must wait a second after it (RFC 6762 §6).
        let sends = copies.iter().zip(probed).map(|((at, _), p)| (*at, *p));
        let Some(rep) = repeats_except(sends.collect()) else {
            return;
        };
        // Repeats only because the responder answers each query several
        // times: one finding for the responder (`check_bursts`), none
        // per row (#442).
        let Some(min_gap) = bursts.unexplained else {
            return;
        };
        // The row stands for repeats across queries: their shortest gap,
        // not one inside a burst, which the copies-per-query count names.
        let rep = Repeats { min_gap, ..rep };
        let per_query = if bursts.per_query > 1 {
            format!(", up to {} copies per query", bursts.per_query)
        } else {
            String::new()
        };
        // What drove the repeats: probe answers answered the probe.
        let trigger = copies
            .iter()
            .zip(probed)
            .rev()
            .filter(|(_, p)| !**p)
            .find_map(|((at, packet), _)| self.trigger(rec, *at, *packet))
            .map(|t| format!(", answering {t}"))
            .unwrap_or_default();
        // How many judged copies (probe answers aside) followed one of
        // our own queries (#431): did mex provoke the repeats?
        let judged: Vec<&(Instant, usize)> = copies
            .iter()
            .zip(probed)
            .filter(|(_, p)| !**p)
            .map(|(copy, _)| copy)
            .collect();
        let after_own = judged
            .iter()
            .filter(|(at, packet)| {
                let names = self.packet_names(*packet);
                let asked = self.own_askings(rec, *at, &names).next().is_some();
                asked
            })
            .count();
        let caused = if after_own > 0 {
            format!(", {after_own} of {} after mex's own queries", judged.len())
        } else {
            String::new()
        };
        out.push(Anomaly {
            kind: AnomalyKind::MulticastRateLimit,
            severity: Severity::Warning,
            service: service.to_string(),
            record_name: Some(rec.name.clone()),
            rtype: Some(rec.rtype),
            rtype_str: Some(rec.rtype_str.clone()),
            rdata: Some(rec.rdata.clone()),
            source: Some(rec.source_label()),
            message: format!("{}{per_query}{caused}{trigger}", rep.describe("multicast")),
            rfc: "RFC 6762 §6",
            requirement: "MUST NOT",
            response: None,
            responders: Vec::new(),
        });
    }
}
