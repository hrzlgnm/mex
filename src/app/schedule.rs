// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// Query scheduling state (RFC 6762 §5.2, §5.4, §7.1, §7.3).
///
/// Owns the continuous-browsing backoff, the per-row cache refresh, the
/// learned service types and enumeration known answers, query provenance,
/// overheard questions for duplicate suppression, and the transmit hold.
/// Outside `app::schedule` it changes only through these methods; the
/// timing rules themselves still run on `App` here.
#[derive(Default)]
pub(super) struct Scheduler {
    /// Continuous browse schedule per (name, rtype): RFC 6762 §5.2
    /// exponential backoff (1s, 2s, 4s, … capped at 1h). Replaces the old
    /// fixed 60s re-poll. TTL-driven cache refresh lives in `requeries`.
    continuous: HashMap<(String, u16), ContinuousQuery>,
    /// Per continuous stream, the links (interface names) a fresh unique
    /// answer arrived on (#441): the stream asks only the other links,
    /// and is dampened once every usable link is covered. Pruned with
    /// `continuous`.
    covered: HashMap<(String, u16), BTreeSet<String>>,
    /// The usable links at the last `poll_continuous`: a link not among
    /// them is new (just up, newly selected, or back after going away),
    /// and restarts discovery there (#441).
    last_usable: BTreeSet<String>,
    /// A link that became usable runs its own startup stream for each
    /// question (#441), by (question, link): it asks that link alone, so
    /// a reconnecting Wi-Fi never restarts discovery on the other links.
    /// It ends when the link is covered, or joins the question's stream
    /// once its interval has caught up.
    link_streams: HashMap<((String, u16), String), LinkStream>,
    /// Every service type ever learned (enumeration answers, PTR owners,
    /// confirmed services). Persistent: used for instance/type splitting
    /// and as the desired continuous-query set. Never cleared on a timer.
    known_types: HashSet<String>,
    /// Per-interest summary of `refresh_rows` for the UI and dumps:
    /// (earliest next refresh due, highest unanswered count) over the
    /// rows of a (name, type) still being refreshed. Rebuilt by every
    /// `requery_expiring` pass; answers clear it early via push_record.
    requeries: HashMap<(String, u16), (Instant, u8)>,
    /// Refresh schedule per cached row (RFC 6762 §5.2): a querier SHOULD
    /// re-ask at 80% of the row's TTL, then 85/90/95% if no answer
    /// arrives, with ~2% random variation; after four misses the row
    /// expires at 100% (no hourly refresh — hourly is only the cap for
    /// *unanswered* continuous browsing). Rows sharing a question are
    /// tracked separately so each gets its own four attempts on its own
    /// TTL. A re-announcement replaces the row and starts it afresh.
    /// Pruned to live rows in `requery_expiring`.
    refresh_rows: HashMap<RefreshRow, RowRefresh>,
    /// Per-interest query provenance (transmit / suppress / observe),
    /// keyed like `continuous` by (lowercased name, type) — see
    /// `provenance_key`. Pruned with dead interests in `evict_expired`.
    query_history: HashMap<(String, u16), InterestQueryState>,
    /// Enumeration answers learned from `_services._dns-sd._udp.local`
    /// PTR answers: service type -> (original TTL, received_at, ingress
    /// interface). Used as known answers on enumeration requeries
    /// (RFC 6762 §7.1, shared), scoped to the link they came from.
    enum_known: HashMap<String, (u32, Instant, String)>,
    /// Whether the startup QU batch was already sent (RFC 6762 §5.4:
    /// QU only on wake/interface-activation batch, QM afterwards).
    startup_qu_sent: bool,
    /// Queries are on hold because no family can transmit (no usable
    /// link on either, or `-i` naming only down links): nothing is
    /// counted as sent and no schedule advances until one resumes.
    transmit_held: bool,
    /// Recently overheard QM questions from other queriers (RFC 6762 §7.3):
    /// key (lowercased name, type) -> (seen_at, remote KA targets lowercased
    /// and dot-trimmed, ingress iface). Consumed to suppress our own
    /// duplicate once; pruned after OVERHEARD_WINDOW. Own loopback and QU
    /// questions are never stored.
    overheard: HashMap<(String, u16), (Instant, HashSet<String>, String)>,
}

impl Scheduler {
    /// Learn a service type from an enumeration answer and track it as a
    /// known answer (RFC 6762 §7.1) until it expires or says goodbye.
    pub(super) fn note_enum_type(&mut self, target: &str, rec: &browse::RawRecord) {
        let key = target.to_ascii_lowercase();
        self.known_types.insert(key.clone());
        if rec.ttl > 0 {
            self.enum_known
                .insert(key, (rec.ttl, rec.received_at, rec.iface.clone()));
        } else {
            self.enum_known.remove(&key);
        }
    }

    /// Every learned service type, from enumeration or announcements.
    pub(super) fn type_names(&self) -> impl Iterator<Item = &String> {
        self.known_types.iter().chain(self.enum_known.keys())
    }

    /// An answer refreshed this interest: its refresh summary is done.
    pub(super) fn refresh_answered(&mut self, key: &(String, u16)) {
        self.requeries.remove(key);
    }

    /// RFC 6762 §5.2: a unique answer ends discovery for this interest;
    /// the 80%-TTL refresh takes over.
    /// Note that a fresh unique answer for `key` arrived on `link`
    /// (#441). Returns whether every usable link is covered now (or none
    /// is known), so the stream can be dampened everywhere.
    pub(super) fn cover(
        &mut self,
        key: &(String, u16),
        link: String,
        usable: &BTreeSet<String>,
    ) -> bool {
        self.link_streams.remove(&(key.clone(), link.clone()));
        let cover = self.covered.entry(key.clone()).or_default();
        cover.insert(link);
        usable.is_empty() || usable.is_subset(cover)
    }

    pub(super) fn dampen(&mut self, key: &(String, u16)) {
        if let Some(entry) = self.continuous.get_mut(key) {
            entry.interval = MAX_CONTINUOUS_INTERVAL;
            entry.next_due = Instant::now() + MAX_CONTINUOUS_INTERVAL;
        }
    }

    /// Query provenance of one interest (`App::provenance_key`).
    pub(super) fn history(&self, key: &(String, u16)) -> Option<&InterestQueryState> {
        self.query_history.get(key)
    }

    pub(super) fn continuous(&self) -> &HashMap<(String, u16), ContinuousQuery> {
        &self.continuous
    }

    pub(super) fn known_types(&self) -> &HashSet<String> {
        &self.known_types
    }

    pub(super) fn requeries(&self) -> &HashMap<(String, u16), (Instant, u8)> {
        &self.requeries
    }

    pub(super) fn query_history(&self) -> &HashMap<(String, u16), InterestQueryState> {
        &self.query_history
    }

    pub(super) fn enum_known(&self) -> &HashMap<String, (u32, Instant, String)> {
        &self.enum_known
    }

    /// Map key for `continuous` and `requeries`: the name with ASCII
    /// letters lowercased. mDNS names compare case-insensitively for
    /// A-Z only; every other byte, UTF-8 multibyte characters included,
    /// compares exactly (RFC 6762 §16, RFC 4343 §3), so `É` and `é` stay
    /// distinct names. The query itself keeps wire case via `qname` /
    /// the desired-map value.
    pub(super) fn continuous_key(name: &str, rtype: u16) -> (String, u16) {
        (name.to_ascii_lowercase(), rtype)
    }

    /// Provenance map key: dot-trimmed, ASCII-lowercased name plus type,
    /// so wire case and trailing dots collapse the way the scheduler keys
    /// do (RFC 6762 §16: only A-Z fold).
    pub(super) fn provenance_key(name: &str, rtype: u16) -> (String, u16) {
        (name.trim_end_matches('.').to_ascii_lowercase(), rtype)
    }

    /// Record an observed remote question with its packet timestamp,
    /// querier, and ingress interface, so dumps can identify which link
    /// and browser asked (RFC 6762 §5.4/§11 context).
    pub(super) fn note_observed(&mut self, q: &browse::RawRecord, from: std::net::SocketAddr) {
        let entry = self
            .query_history
            .entry(Self::provenance_key(&q.name, q.rtype))
            .or_default();
        entry.observed = Some(ObservedQuery {
            at: q.received_at,
            from,
            iface: q.iface.clone(),
        });
    }

    /// The question a response record most likely answered: the latest
    /// question for its owner name, any type, ours (transmitted) or a
    /// remote querier's (observed), at most `TRIGGER_WINDOW` before the
    /// record arrived. mDNS responses carry no question section
    /// (RFC 6762 §6), so timing is all there is. Provenance keeps only the
    /// latest timestamp per interest, which is why this runs at ingest.
    pub(super) fn response_trigger(&self, rec: &browse::RawRecord) -> Option<browse::QueryTrigger> {
        let name = Self::provenance_key(&rec.name, rec.rtype).0;
        self.query_history
            .iter()
            .filter(|((n, _), _)| *n == name)
            .flat_map(|((_, rtype), state)| {
                [
                    (state.transmitted, true),
                    (state.observed.as_ref().map(|o| o.at), false),
                ]
                .into_iter()
                .filter_map(move |(at, own)| at.map(|at| (at, own, *rtype)))
            })
            .filter(|(at, _, _)| {
                *at <= rec.received_at && rec.received_at.duration_since(*at) <= TRIGGER_WINDOW
            })
            .max_by_key(|(at, _, _)| *at)
            .map(|(_, own, rtype)| browse::QueryTrigger {
                question: format!(
                    "{}. {}",
                    rec.name.trim_end_matches('.'),
                    browse::rtype_label(rtype)
                ),
                own,
            })
    }

    /// The link an overheard copy of `key` arrived on, while it can still
    /// stand in for ours (`suppressed_by_overheard`); `None` when there is
    /// none or its link is unknown.
    pub(super) fn overheard_link(&self, key: &(String, u16)) -> Option<String> {
        let lookup = (key.0.trim_end_matches('.').to_ascii_lowercase(), key.1);
        self.overheard
            .get(&lookup)
            .filter(|(seen, _, iface)| seen.elapsed() < OVERHEARD_WINDOW && !iface.is_empty())
            .map(|(_, _, iface)| iface.clone())
    }

    /// RFC 6762 §7.3: if we overheard the same QM question recently and its
    /// Known-Answer section holds nothing we wouldn't send ourselves,
    /// treat our query as sent. Consumes the entry so one overheard query
    /// suppresses one transmission. `local_ka` is the KA list we computed
    /// for the send; filtering is scoped to the link the overheard query
    /// arrived on.
    pub(super) fn suppressed_by_overheard(
        &mut self,
        key: &(String, u16),
        local_ka: &[browse::KnownAnswer],
    ) -> bool {
        let lookup = (key.0.trim_end_matches('.').to_ascii_lowercase(), key.1);
        let (seen, remote, iface) = match self.overheard.get(&lookup) {
            Some(v) => v.clone(),
            None => return false,
        };
        if seen.elapsed() >= OVERHEARD_WINDOW {
            return false;
        }
        let mut local = HashSet::new();
        for ka in local_ka {
            if ka.iface.is_empty() || iface.is_empty() || ka.iface == iface {
                local.insert(ka.target.trim_end_matches('.').to_ascii_lowercase());
            }
        }
        if remote.iter().all(|r| local.contains(r)) {
            self.overheard.remove(&lookup);
            return true;
        }
        false
    }

    pub(super) fn advance_continuous(&mut self, key: &(String, u16), now: Instant) {
        if let Some(entry) = self.continuous.get_mut(key) {
            let current = entry.interval.max(Duration::from_secs(1));
            entry.next_due = now + current;
            entry.interval = (current * 2).min(MAX_CONTINUOUS_INTERVAL);
        }
    }

    /// Postpone the exponential stream after a refresh (real or suppressed)
    /// so the two §5.2 timers don't emit back-to-back duplicates.
    pub(super) fn postpone_continuous_for_refresh(&mut self, key: &(String, u16), now: Instant) {
        // Refresh keys keep wire case; streams are keyed by
        // `continuous_key`, so look the stream up by that key.
        use std::collections::hash_map::Entry;
        match self.continuous.entry(Self::continuous_key(&key.0, key.1)) {
            Entry::Occupied(mut e) => {
                let entry = e.get_mut();
                let floor = now + entry.interval.max(Duration::from_secs(1));
                if entry.next_due < floor {
                    entry.next_due = floor;
                }
            }
            Entry::Vacant(e) => {
                e.insert(ContinuousQuery {
                    next_due: now + Duration::from_secs(1),
                    interval: Duration::from_secs(1),
                    qname: key.0.clone(),
                });
            }
        }
    }

    /// Postpone an existing exponential stream after a manual query
    /// (#394), like a refresh does, but never start one: a manual query
    /// creates no schedule.
    pub(super) fn postpone_continuous_for_manual(&mut self, key: &(String, u16), now: Instant) {
        if let Some(entry) = self
            .continuous
            .get_mut(&Self::continuous_key(&key.0, key.1))
        {
            let floor = now + entry.interval.max(Duration::from_secs(1));
            if entry.next_due < floor {
                entry.next_due = floor;
            }
        }
    }

    /// Record our own transmit or suppression for an interest, with the
    /// links a transmit went out on.
    pub(super) fn note_query(
        &mut self,
        name: &str,
        rtype: u16,
        origin: OwnQuery,
        at: Instant,
        interfaces: String,
    ) {
        let entry = self
            .query_history
            .entry(Self::provenance_key(name, rtype))
            .or_default();
        match origin {
            OwnQuery::Transmitted => {
                entry.transmitted = Some(at);
                entry.transmitted_interfaces = interfaces;
            }
            // A manual send is a transmit too (spacing, demand, links).
            OwnQuery::Manual => {
                entry.transmitted = Some(at);
                entry.transmitted_interfaces = interfaces;
                entry.manual = Some(at);
            }
            OwnQuery::Suppressed => entry.suppressed = Some(at),
        }
    }

    /// Remember a remote QM question and the known answers it carried
    /// (RFC 6762 §7.3), to suppress our own duplicate once.
    pub(super) fn note_overheard(&mut self, q: &browse::RawRecord, kas: &[browse::RawRecord]) {
        let key = (q.name.trim_end_matches('.').to_ascii_lowercase(), q.rtype);
        let mut remote = HashSet::new();
        for ka in kas {
            if ka.rtype == q.rtype && ka.name.eq_ignore_ascii_case(&q.name) {
                remote.insert(ka.rdata.trim_end_matches('.').to_ascii_lowercase());
            }
        }
        self.overheard
            .insert(key, (Instant::now(), remote, q.iface.clone()));
    }

    /// Prune schedules to live interests. `live` holds every
    /// (lowercased name, type) the cache still has; enumeration known
    /// answers are added here before they expire at 100% TTL.
    pub(super) fn evict(&mut self, mut live: HashSet<(String, u16)>) {
        for t in self.enum_known.keys() {
            live.insert((t.clone(), 12));
        }
        self.requeries
            .retain(|k, _| live.contains(&(k.0.to_ascii_lowercase(), k.1)));
        self.continuous.retain(|k, _| live.contains(k));
        self.covered.retain(|k, _| live.contains(k));
        // Provenance outlives short schedule gaps but not dead
        // interests: keep entries with a live schedule key or a recent
        // event, so a recently expired interest still reports its
        // terminal state in dumps.
        self.query_history.retain(|k, v| {
            live.contains(k)
                || [
                    v.transmitted,
                    v.suppressed,
                    v.observed.as_ref().map(|o| o.at),
                ]
                .into_iter()
                .flatten()
                .any(|t| t.elapsed() < INTEREST_GRACE)
        });
        // Overheard QM queries are single-use and short-lived (§7.3).
        self.overheard
            .retain(|_, (seen, _, _)| seen.elapsed() < OVERHEARD_WINDOW);
        // Expire enumeration known answers at 100% TTL; prune the type
        // cache to live interests so it cannot grow without bound.
        self.enum_known
            .retain(|_, (ttl, received, _)| received.elapsed().as_secs() as u32 <= *ttl);
        let live_types: HashSet<String> = live
            .iter()
            .filter(|(_, t)| *t == 12)
            .map(|(n, _)| n.clone())
            .collect();
        self.known_types.retain(|t| live_types.contains(t));
    }

    /// Drop the overheard copy of a question our own manual query just
    /// asked (#394): it must not stand in for a later scheduled send.
    pub(super) fn forget_overheard(&mut self, name: &str, rtype: u16) {
        self.overheard.remove(&Self::provenance_key(name, rtype));
    }
}

/// Direct state access for tests that set up a schedule.
#[cfg(test)]
impl Scheduler {
    pub(super) fn refresh_rows(&self) -> &HashMap<RefreshRow, RowRefresh> {
        &self.refresh_rows
    }

    pub(super) fn overheard(&self) -> &HashMap<(String, u16), (Instant, HashSet<String>, String)> {
        &self.overheard
    }

    pub(super) fn overheard_mut(
        &mut self,
    ) -> &mut HashMap<(String, u16), (Instant, HashSet<String>, String)> {
        &mut self.overheard
    }

    #[cfg(test)]
    pub(super) fn link_streams_mut(&mut self) -> &mut HashMap<((String, u16), String), LinkStream> {
        &mut self.link_streams
    }

    pub(super) fn continuous_mut(&mut self) -> &mut HashMap<(String, u16), ContinuousQuery> {
        &mut self.continuous
    }

    pub(super) fn known_types_mut(&mut self) -> &mut HashSet<String> {
        &mut self.known_types
    }

    pub(super) fn requeries_mut(&mut self) -> &mut HashMap<(String, u16), (Instant, u8)> {
        &mut self.requeries
    }

    pub(super) fn refresh_rows_mut(&mut self) -> &mut HashMap<RefreshRow, RowRefresh> {
        &mut self.refresh_rows
    }

    pub(super) fn query_history_mut(&mut self) -> &mut HashMap<(String, u16), InterestQueryState> {
        &mut self.query_history
    }

    pub(super) fn startup_qu_sent_mut(&mut self) -> &mut bool {
        &mut self.startup_qu_sent
    }
}

impl App {
    /// Per-interest summary for the TUI: latest event age/kind,
    /// owning timer and deadline, plus whether local demand ever
    /// existed. Unknown names yield an empty summary with blank cells.
    pub fn interest_summary(&self, name: &str, rtype: u16) -> InterestSummary {
        let now = Instant::now();
        let view = self.interest_view(&Scheduler::provenance_key(name, rtype));
        InterestSummary {
            timer: view.timer,
            next_due_in_secs: view
                .next_due
                .map(|d| d.saturating_duration_since(now).as_secs()),
            had_local_demand: view
                .state
                .as_ref()
                .is_some_and(|s| s.transmitted.is_some() || s.suppressed.is_some()),
            last_transmitted_at: view.at(QueryOrigin::Transmitted),
            last_suppressed_at: view.at(QueryOrigin::Suppressed),
            last_manual_at: view.at(QueryOrigin::Manual),
        }
    }

    pub(super) fn remaining_ttl(rec: &browse::RawRecord) -> u32 {
        rec.ttl
            .saturating_sub(rec.received_at.elapsed().as_secs() as u32)
    }

    /// Known PTR answers for a service type (or enumeration), RFC 6762 §7.1:
    /// only answers with at least half of the original TTL remaining, sent
    /// with their remaining TTL so responders can suppress duplicates.
    /// Unique types (SRV/TXT/A/AAAA) are intentionally omitted: §7.1 notes
    /// known-answer suppression is for shared answers. Each answer carries
    /// the interface it was observed on; the transport only sends it back
    /// out that same link, where it can actually suppress something.
    pub(super) fn known_ptrs(&self, owner: &str) -> Vec<browse::KnownAnswer> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        let mut push_rec = |rec: &browse::RawRecord, out: &mut Vec<browse::KnownAnswer>| {
            if rec.rtype != 12 || rec.ttl == 0 {
                return;
            }
            let remaining = Self::remaining_ttl(rec);
            // u64: twice a 32-bit TTL overflows u32.
            if u64::from(remaining) * 2 < u64::from(rec.ttl) {
                return;
            }
            let target = rec.rdata.trim_end_matches('.').to_string();
            if seen.insert((target.clone(), rec.iface.clone())) {
                out.push(browse::KnownAnswer {
                    target,
                    ttl: remaining,
                    iface: rec.iface.clone(),
                });
            }
        };
        for s in &self.services {
            if !s.service_type.eq_ignore_ascii_case(owner) {
                continue;
            }
            for rec in &s.answers {
                push_rec(rec, &mut out);
            }
        }
        for p in &self.pending_instances {
            if !p.service_type.eq_ignore_ascii_case(owner) {
                continue;
            }
            for rec in &p.answers {
                push_rec(rec, &mut out);
            }
        }
        out
    }

    pub(super) fn known_enum_answers(&self) -> Vec<browse::KnownAnswer> {
        let now = Instant::now();
        let mut out = Vec::new();
        for (svc_type, (ttl, received, iface)) in &self.scheduler.enum_known {
            let elapsed = now.duration_since(*received).as_secs() as u32;
            let remaining = ttl.saturating_sub(elapsed);
            if *ttl == 0 || u64::from(remaining) * 2 < u64::from(*ttl) {
                continue;
            }
            out.push(browse::KnownAnswer {
                target: svc_type.clone(),
                ttl: remaining,
                iface: iface.clone(),
            });
        }
        out
    }

    pub(super) fn requery_expiring(&mut self) {
        self.update_refreshes(true);
    }

    /// Track live rows' refresh state and rebuild the per-question
    /// summaries; with `send`, also fire due refresh queries. Without
    /// it (transmission on hold) nothing is sent and no attempt is used:
    /// expired or replaced rows just drop out.
    pub(super) fn update_refreshes(&mut self, send: bool) {
        let now = Instant::now();
        // Live rows inside their 80% window with attempts left, grouped by
        // question, each flagged whether its own next attempt is due.
        // Several rows (sources, rdata) share one question; each keeps
        // its own TTL and count, so one row can neither set another's
        // pace nor use up its attempts. Expired rows (elapsed > TTL) are
        // not refreshed: RFC 6762 §5.2 deletes the record at 100% after
        // four unanswered queries.
        let mut pending: HashMap<(String, u16), Vec<PendingRow>> = HashMap::new();
        let mut live_rows: HashSet<RefreshRow> = HashSet::new();
        let tracked = &self.scheduler.refresh_rows;
        let mut scan = |rec: &browse::RawRecord| {
            if rec.ttl == 0 {
                return;
            }
            match rec.rtype {
                12 | 33 | 16 | 1 | 28 => {}
                _ => return,
            }
            let elapsed = rec.received_at.elapsed().as_secs() as u32;
            if elapsed > rec.ttl {
                return;
            }
            let row = refresh_row(rec);
            // One A/AAAA row is filed under every service of its host;
            // count it once, or a single query would use up several of
            // its attempts.
            if !live_rows.insert(row.clone()) || !in_refresh_window(elapsed, rec.ttl) {
                return;
            }
            let state = tracked.get(&row);
            if state.is_some_and(|s| s.attempts >= REFRESH_ATTEMPTS) {
                return;
            }
            let due = state.is_none_or(|s| now >= s.next_due);
            pending
                .entry((row.0.clone(), row.1))
                .or_default()
                .push((row, rec.ttl, due));
        };
        for svc in &self.services {
            svc.answers.iter().for_each(&mut scan);
        }
        for entry in &self.enum_entries {
            entry.answers.iter().for_each(&mut scan);
        }
        // Pending instances (PTR seen, SRV not yet) keep their rows fresh
        // too: their unique answers dampen discovery, so this refresh is
        // what maintains them.
        for p in &self.pending_instances {
            p.answers.iter().for_each(&mut scan);
        }
        // No maintenance without a live record (RFC 6762 §5.2 deletes at
        // 100%); a replaced row is gone with its old identity.
        self.scheduler
            .refresh_rows
            .retain(|r, _| live_rows.contains(r));
        let fired: Vec<_> = if send {
            pending
                .iter()
                .filter(|(_, rows)| rows.iter().any(|(_, _, due)| *due))
                // A manual query (#394) under a second old already asked
                // this: hold the refresh (attempt kept, still due) until
                // the RFC 6762 §5.2 spacing has passed.
                .filter(|(key, _)| {
                    !self
                        .scheduler
                        .history(&Scheduler::provenance_key(&key.0, key.1))
                        .and_then(|h| h.manual)
                        .is_some_and(|t| now.saturating_duration_since(t) < MANUAL_REFRESH_SPACING)
                })
                .map(|(key, _)| key.clone())
                .collect()
        } else {
            Vec::new()
        };
        if !fired.is_empty() {
            log::debug!(
                "mex: cache refresh triggered for {} interest(s)",
                fired.len()
            );
        }
        for key in fired {
            if !self.send_refresh(&key, now) {
                continue;
            }
            // 0-2% random variation so queriers do not stay in lockstep
            // (RFC 6762 §5.2: 80-82%, 85-87%, 90-92%, 95-97%). No 1s floor
            // here: the >=1s rule applies to the continuous stream, while
            // refresh spacing is 5% of the TTL (floors would push small
            // TTLs past 100%). Only rows whose own attempt was due count
            // this query; the others keep their pace.
            let jitter_pct = rand_u32() % 201;
            for (row, ttl, due) in &pending[&key] {
                if !due {
                    continue;
                }
                let state = self
                    .scheduler
                    .refresh_rows
                    .entry(row.clone())
                    .or_insert(RowRefresh {
                        next_due: now,
                        attempts: 0,
                    });
                state.attempts += 1;
                state.next_due = now + refresh_step(*ttl, jitter_pct);
            }
        }
        // Per-question summary for the UI: rows that used up their four
        // attempts drop out and are left to expire at 100%.
        self.scheduler.requeries.clear();
        for (key, rows) in pending {
            let summary = rows
                .iter()
                .filter_map(|(row, _, _)| self.scheduler.refresh_rows.get(row))
                .filter(|s| s.attempts < REFRESH_ATTEMPTS)
                .fold(None, |acc: Option<(Instant, u8)>, s| {
                    Some(match acc {
                        Some((due, n)) => (due.min(s.next_due), n.max(s.attempts)),
                        None => (s.next_due, s.attempts),
                    })
                });
            if let Some(summary) = summary {
                self.scheduler.requeries.insert(key, summary);
            }
        }
    }

    /// Transmit one refresh query for `key`, or count it as sent when an
    /// overheard query already asked it (RFC 6762 §7.3). Returns whether
    /// the attempt counts (false only for an unsupported record type).
    pub(super) fn send_refresh(&mut self, key: &(String, u16), now: Instant) -> bool {
        let Some(rt) = browse::record_type_from_u16(key.1) else {
            return false;
        };
        let ka = if rt == TYPE::PTR {
            if is_enum_name(&key.0) {
                self.known_enum_answers()
            } else {
                self.known_ptrs(&key.0)
            }
        } else {
            Vec::new()
        };
        // §7.3 per link (#441): overheard on one of several links, the
        // refresh still goes out on the others.
        if let Some(links) = self.overheard_scope(key, &ka, &[]) {
            self.diagnostics.q_sent_refresh += 1;
            self.diagnostics.ka_sent += ka.len() as u64;
            self.queue_question(browse::QueryRequest {
                name: key.0.clone(),
                record_type: rt,
                known_answers: ka,
                qu: false,
                links,
            });
        } else {
            log::debug!("mex: suppressed refresh query for {} (overheard)", key.0);
            self.diagnostics.suppressed_refresh += 1;
            self.diagnostics.suppressed_times.push_back(now);
            self.note_query(&key.0, key.1, OwnQuery::Suppressed, now);
        }
        self.route_own_question(&key.0, key.1, false);
        // A refresh query also elicits new answers, so postpone the
        // exponential stream for the same question: otherwise the two
        // timers can fire on the same tick and emit back-to-back
        // duplicates (RFC 6762 §5.2 spacing).
        self.scheduler.postpone_continuous_for_refresh(key, now);
        true
    }

    /// Send the `self` question under the Questions cursor once, now
    /// (#394). A one-off nudge: it uses no refresh attempt and moves no
    /// backoff. No popup: a send shows as `manual` in the row's LAST;
    /// a press that sends nothing is only logged.
    pub(super) fn manual_refresh_selected(&mut self) {
        if let Err(why) = self.try_manual_refresh() {
            log::debug!("mex: manual query not sent: {why}");
        }
    }

    fn try_manual_refresh(&mut self) -> Result<(), String> {
        if self.passive {
            return Err("passive mode sends no queries".to_string());
        }
        // Like the schedules' hold: nothing queued, nothing counted.
        if !self.query_tx.transmit().any() {
            return Err("queries on hold (no link can transmit)".to_string());
        }
        let Some(DetailEntry::Question {
            name,
            rtype_str,
            source,
            ..
        }) = self.selected_detail_entry()
        else {
            return Err("no question row selected".to_string());
        };
        if *source != SELF_SOURCE {
            return Err(format!("{name} {rtype_str} is a foreign question"));
        }
        let name = name.trim_end_matches('.').to_string();
        let rtype_str = rtype_str.to_string();
        let Some((rtype, rt)) = browse::rtype_from_str(&rtype_str)
            .and_then(|code| browse::record_type_from_u16(code).map(|rt| (code, rt)))
        else {
            return Err(format!("{rtype_str} is never queried"));
        };
        // An NSEC-denied address type drives no query interest for this
        // service, even while its old self row is still listed. Host
        // scoped like the scheduler: a denial for an old SRV target
        // never blocks the new one.
        if let Some(DetailTarget::Service(svc)) = self.display_detail() {
            let key = service_key(&svc.instance, &svc.service_type);
            if self
                .address_denials
                .covers(&key, rtype, &name.to_ascii_lowercase())
            {
                return Err(format!("{name} {rtype_str} is denied by NSEC"));
            }
        }
        let now = Instant::now();
        // RFC 6762 §5.2 spacing: never the same question twice within a
        // second, so key repeat cannot flood the link and a press cannot
        // land on top of a scheduled send.
        let last = self
            .scheduler
            .history(&Scheduler::provenance_key(&name, rtype))
            .and_then(|h| h.transmitted);
        if last.is_some_and(|t| now.saturating_duration_since(t) < MANUAL_REFRESH_SPACING) {
            return Err(format!("{name} {rtype_str} was sent less than 1s ago"));
        }
        let ka = if rt == TYPE::PTR {
            if is_enum_name(&name) {
                self.known_enum_answers()
            } else {
                self.known_ptrs(&name.to_ascii_lowercase())
            }
        } else {
            Vec::new()
        };
        let ka_count = ka.len() as u64;
        // Immediate, alone: a nudge doesn't wait for the tick's batch.
        if !self.query_tx.send(vec![browse::QueryRequest {
            name: name.clone(),
            record_type: rt,
            known_answers: ka,
            qu: false,
            links: Vec::new(),
        }]) {
            log::warn!("mex: dropped manual query for {name} (listener channels closed)");
            return Ok(());
        }
        log::debug!("mex: sending manual query for {name} {rtype_str}");
        self.diagnostics.q_sent_manual += 1;
        self.diagnostics.ka_sent += ka_count;
        self.note_query(&name, rtype, OwnQuery::Manual, now);
        // Our query answers whatever an overheard identical question
        // asked: it must not later stand in for a scheduled send (§7.3).
        self.scheduler.forget_overheard(&name, rtype);
        self.route_own_question(&name, rtype, false);
        self.scheduler
            .postpone_continuous_for_manual(&(name.clone(), rtype), now);
        Ok(())
    }

    /// Add a due question to this tick's batch (#430). One asked twice in
    /// a tick (stream and refresh) goes in once: names fold ASCII-only
    /// (RFC 6762 §16), the known answers are the union and the QU bit
    /// sticks.
    pub(super) fn queue_question(&mut self, req: browse::QueryRequest) {
        let same = |q: &browse::QueryRequest| {
            q.record_type == req.record_type
                && q.name
                    .trim_end_matches('.')
                    .eq_ignore_ascii_case(req.name.trim_end_matches('.'))
        };
        let Some(queued) = self.outbox.iter_mut().find(|q| same(q)) else {
            self.outbox.push(req);
            return;
        };
        queued.qu |= req.qu;
        // Every link (empty) wins; otherwise ask the union of both.
        if queued.links.is_empty() || req.links.is_empty() {
            queued.links.clear();
        } else {
            for link in req.links {
                if !queued.links.contains(&link) {
                    queued.links.push(link);
                }
            }
        }
        for ka in req.known_answers {
            if !queued
                .known_answers
                .iter()
                .any(|k| k.iface == ka.iface && k.target.eq_ignore_ascii_case(&ka.target))
            {
                queued.known_answers.push(ka);
            }
        }
    }

    /// Send this tick's questions as one batch: the listener packs them
    /// into as few packets as fit per egress interface and family. Each
    /// question is noted as transmitted once the listener takes the
    /// batch; a closed channel drops them all, logged.
    pub(super) fn flush_outbox(&mut self) {
        if self.outbox.is_empty() {
            return;
        }
        let batch = std::mem::take(&mut self.outbox);
        let asked: Vec<(String, u16, Vec<String>)> = batch
            .iter()
            .map(|q| (q.name.clone(), u16::from(q.record_type), q.links.clone()))
            .collect();
        if !self.query_tx.send(batch) {
            log::warn!(
                "mex: dropped {} queued question(s) (listener channels closed)",
                asked.len()
            );
            return;
        }
        let now = Instant::now();
        for (name, rtype, links) in asked {
            self.note_query_on(&name, rtype, OwnQuery::Transmitted, now, &links);
        }
    }

    /// Record a query event for an interest: we transmitted it or §7.3
    /// suppression stood in for it, stamped at action time.
    pub(super) fn note_query(&mut self, name: &str, rtype: u16, origin: OwnQuery, at: Instant) {
        self.note_query_on(name, rtype, origin, at, &[]);
    }

    /// `note_query` for a query sent only on `links` (#441), recorded as
    /// its interfaces; empty for every usable link.
    pub(super) fn note_query_on(
        &mut self,
        name: &str,
        rtype: u16,
        origin: OwnQuery,
        at: Instant,
        links: &[String],
    ) {
        let mut query_interfaces: Vec<String> = self
            .link_stats
            .v4
            .iter()
            .map(|(name, _)| name.clone())
            .chain(self.link_stats.v6.iter().map(|(name, _)| name.clone()))
            .filter(|name| {
                self.interfaces
                    .as_ref()
                    .is_none_or(|selected| selected.contains(name))
            })
            .collect();
        if !links.is_empty() {
            query_interfaces = links.to_vec();
        }
        query_interfaces.sort();
        query_interfaces.dedup();
        let query_interfaces = query_interfaces.join(", ");
        self.scheduler
            .note_query(name, rtype, origin, at, query_interfaces);
    }

    /// Whether a live (unexpired, nonzero-TTL) answer row exists for a
    /// normalized interest key, across services, enumeration, and
    /// pending instances.
    pub(super) fn has_live_answer(&self, key: &(String, u16)) -> bool {
        let live_row = |rec: &browse::RawRecord| {
            // Canonical key comparison: wire case of A-Z folds, other
            // bytes compare exactly (RFC 6762 §16).
            Scheduler::provenance_key(&rec.name, rec.rtype).0 == key.0
                && rec.ttl > 0
                && Self::remaining_ttl(rec) > 0
        };
        self.services
            .iter()
            .any(|s| s.answers.iter().any(&live_row))
            || self
                .enum_entries
                .iter()
                .any(|e| e.answers.iter().any(&live_row))
            || self
                .pending_instances
                .iter()
                .any(|p| p.answers.iter().any(&live_row))
            || self.pending_addrs.values().flatten().any(live_row)
    }

    /// Earliest point at which the refresh scan will trigger for an
    /// interest: 80% of TTL past each live row's receipt, minimum
    /// across rows. Matches the scan's coverage exactly (services,
    /// enumeration answers and pending instances, browsable types only) so the projection
    /// never predicts a refresh the scheduler would not send. `None`
    /// in passive mode: a passive browser transmits nothing, so no
    /// refresh is ever due.
    pub(super) fn next_refresh_due(&self, key: &(String, u16)) -> Option<Instant> {
        if self.passive {
            return None;
        }
        let deadline = |rec: &browse::RawRecord| {
            if rec.ttl == 0 {
                return None;
            }
            match rec.rtype {
                12 | 33 | 16 | 1 | 28 => {}
                _ => return None,
            }
            if rec.rtype != key.1
                || Scheduler::provenance_key(&rec.name, rec.rtype).0 != key.0
                || rec.received_at.elapsed().as_secs() as u32 > rec.ttl
            {
                return None;
            }
            // Rows that used up their four attempts only wait to expire.
            if self
                .scheduler
                .refresh_rows
                .get(&refresh_row(rec))
                .is_some_and(|s| s.attempts >= REFRESH_ATTEMPTS)
            {
                return None;
            }
            // Earliest whole second satisfying the scan's trigger.
            Some(rec.received_at + Duration::from_secs((rec.ttl as u64 * 4).div_ceil(5)))
        };
        let earliest = self
            .services
            .iter()
            .flat_map(|s| s.answers.iter())
            .chain(self.enum_entries.iter().flat_map(|e| e.answers.iter()))
            .chain(self.pending_instances.iter().flat_map(|p| p.answers.iter()))
            .filter_map(deadline)
            .min()?;
        // A row already past 80% with no entry yet fires on the next
        // tick: clamp to now instead of showing a stale past deadline.
        Some(earliest.max(Instant::now()))
    }

    /// Authoritative per-interest snapshot for dumps and the TUI.
    /// Refresh state wins over the continuous stream (urgent TTL
    /// maintenance outranks hourly rediscovery); with no schedule the
    /// interest is terminal. Status distinguishes a pending send from
    /// suppression, and a quiet interest with live answers (answered)
    /// from one with nothing left (abandoned).
    pub(super) fn interest_view(&self, key: &(String, u16)) -> InterestView {
        // Canonicalize once: map keys keep wire case or are lowercased
        // depending on the map, so compare through `provenance_key`
        // everywhere (A-Z fold, other bytes exact: RFC 6762 §16).
        let key = Scheduler::provenance_key(&key.0, key.1);
        let state = self.scheduler.query_history.get(&key).cloned();
        let (attempt, refresh_due) = self
            .scheduler
            .requeries
            .iter()
            .find(|(k, _)| Scheduler::provenance_key(&k.0, k.1) == key)
            .map(|(_, (due, count))| (*count, Some(*due)))
            .unwrap_or((0, None));
        let browse_due = self
            .scheduler
            .continuous
            .iter()
            .find(|(k, _)| Scheduler::provenance_key(&k.0, k.1) == key)
            .map(|(_, e)| e.next_due);
        let (timer, next_due) = match (refresh_due, browse_due) {
            (Some(due), _) => (TimerKind::Refresh, Some(due)),
            (None, Some(due)) => match self.next_refresh_due(&key) {
                // Projected refresh beats the browse stream: the
                // earlier maintenance owns DUE.
                Some(proj) if proj < due => (TimerKind::Refresh, Some(proj)),
                _ => (TimerKind::Browse, Some(due)),
            },
            // No schedule at all, but live rows would still trigger one:
            // the scheduler fires regardless of continuous membership
            // (except passive mode, which never transmits).
            (None, None) => match self.next_refresh_due(&key) {
                Some(proj) => (TimerKind::Refresh, Some(proj)),
                None => (TimerKind::Expired, None),
            },
        };
        let last_own = state.as_ref().and_then(|s| {
            [
                (QueryOrigin::Transmitted, s.transmitted),
                (QueryOrigin::Suppressed, s.suppressed),
            ]
            .into_iter()
            .filter_map(|(o, t)| t.map(|t| (o, t)))
            .max_by_key(|(_, t)| *t)
            .map(|(o, _)| o)
        });
        // Requery entries are only inserted alongside a send or a
        // suppression decision (never speculatively), so a pending
        // refresh always has a last own action; the Transmitted arm
        // below is the defensive fallback, not a reachable default.
        let status = match (refresh_due.is_some(), last_own) {
            (true, Some(QueryOrigin::Suppressed)) => InterestStatus::Suppressed,
            (true, _) => InterestStatus::Transmitted,
            (false, _) if self.has_live_answer(&key) => InterestStatus::Answered,
            (false, _) => InterestStatus::Abandoned,
        };
        InterestView {
            state,
            attempt,
            next_due,
            timer,
            status,
        }
    }

    /// Strip a dot-separated suffix case-insensitively, returning the
    /// wire-case prefix without the separating dot. The split offset must
    /// be a character boundary: instance names may hold multi-byte UTF-8
    /// (RFC 6763 §4.1.1), so byte-slicing inside a character would panic.
    pub(super) fn strip_suffix_ci<'a>(full: &'a str, suffix: &str) -> Option<&'a str> {
        if full.len() <= suffix.len() {
            return None;
        }
        let off = full.len() - suffix.len();
        if !full.is_char_boundary(off) {
            return None;
        }
        let (prefix, tail) = full.split_at(off);
        if !tail.eq_ignore_ascii_case(suffix) {
            return None;
        }
        // Names are in presentation form: an escaped dot (`\.`) sits
        // inside a label, so the suffix doesn't start a label there.
        prefix
            .strip_suffix('.')
            .filter(|head| !browse::escapes_next(head))
    }

    /// Desired continuous-browse queries: enumeration plus every live PTR /
    /// SRV / TXT / A / AAAA interest, as key -> wire-case name. Derived
    /// from live state each tick so dead services stop costing queries
    /// (RFC 6762 §5.2: no maintenance without active interest).
    pub(super) fn desired_continuous(&self) -> HashMap<(String, u16), String> {
        let mut desired = HashMap::new();
        let mut want = |name: String, rtype: u16| {
            let key = Scheduler::continuous_key(&name, rtype);
            desired.entry(key).or_insert(name);
        };
        want(ENUM_SERVICE.to_string(), 12);
        for t in &self.scheduler.known_types {
            want(t.clone(), 12);
        }
        for p in &self.pending_instances {
            want(p.service_type.clone(), 12);
            let full = crate::browse::instance_name(&p.instance, &p.service_type);
            want(full.clone(), 33);
            want(full, 16);
        }
        for svc in &self.services {
            want(svc.service_type.clone(), 12);
            let full = crate::browse::instance_name(&svc.instance, &svc.service_type);
            want(full.clone(), 33);
            want(full, 16);
            if !svc.hostname.is_empty() {
                // A denied address type is no interest of this service:
                // only other services (or other demand) keep asking.
                let host = svc.hostname.trim_end_matches('.').to_string();
                let key = service_key(&svc.instance, &svc.service_type);
                let host_key = host.to_ascii_lowercase();
                for rtype in [1, 28] {
                    if !self.address_denials.covers(&key, rtype, &host_key) {
                        want(host.clone(), rtype);
                    }
                }
            }
        }
        desired
    }

    pub(super) fn poll_continuous(&mut self) {
        let now = Instant::now();
        let desired = self.desired_continuous();
        // Drop interests that went away (no queries without active interest).
        self.scheduler
            .continuous
            .retain(|k, _| desired.contains_key(k));
        let continuous = &self.scheduler.continuous;
        self.scheduler
            .covered
            .retain(|k, _| continuous.contains_key(k));
        let usable = self.query_links();
        // Streams first seen in this pass share one first-query delay, so
        // questions learned together (a host's addresses with its SRV/TXT)
        // stay due on one tick and keep sharing packets as they double.
        let mut first_delay: Option<Duration> = None;
        self.follow_link_changes(&usable, now, &mut first_delay);
        for (key, qname) in desired {
            let (due, send_name) = match self.scheduler.continuous.get(&key) {
                Some(entry) => (now >= entry.next_due, entry.qname.clone()),
                None => {
                    // RFC 6762 §5.2: first query delayed 20-120ms random.
                    // A unique answer cached before the interest appeared
                    // (e.g. A/AAAA shipped as additionals with the SRV)
                    // means no other answers are forthcoming: start
                    // dampened, as the flush-bit path would, and let the
                    // 80%-TTL refresh maintain it. The interest is still
                    // demand: file its self row now so the Questions pane
                    // shows it pending (LAST "—", DUE the refresh) instead
                    // of hiding it until the first refresh fires.
                    let (unknown_link, mut cover) = self.fresh_unique_cover(&key);
                    // An answer on an unknown link covers every link usable
                    // now, so a link appearing later is still noticed.
                    if unknown_link {
                        cover.extend(usable.iter().cloned());
                    }
                    let all_covered = unknown_link
                        || (!cover.is_empty() && (usable.is_empty() || usable.is_subset(&cover)));
                    if !cover.is_empty() {
                        self.scheduler.covered.insert(key.clone(), cover);
                    }
                    let (next_due, interval) = if all_covered {
                        self.route_own_question(&qname, key.1, false);
                        (now + MAX_CONTINUOUS_INTERVAL, MAX_CONTINUOUS_INTERVAL)
                    } else {
                        let delay = *first_delay.get_or_insert_with(|| rand_range(20, 120));
                        (now + delay, Duration::from_secs(1))
                    };
                    self.scheduler.continuous.insert(
                        key.clone(),
                        ContinuousQuery {
                            next_due,
                            interval,
                            qname: qname.clone(),
                        },
                    );
                    (false, qname)
                }
            };
            if !due {
                continue;
            }
            let Some(rt) = browse::record_type_from_u16(key.1) else {
                continue;
            };
            let ka = self.scheduled_known_answers(&key.0, rt);
            // QU on the first transmission of the enumeration query
            // (RFC 6762 §5.4 startup batch); everything afterwards is QM.
            // First-transmission (interval still 1s) rather than a single
            // flag so the QU survives the 20-120ms first-query delay.
            let qu = key.1 == 12
                && is_enum_name(&key.0)
                && self
                    .scheduler
                    .continuous
                    .get(&key)
                    .is_some_and(|e| e.interval == Duration::from_secs(1));
            // Only the links no fresh unique answer covers yet (#441); none
            // recorded, every link.
            // Links covered, or still on their own link stream, are out.
            let excluded: BTreeSet<&String> = self
                .scheduler
                .covered
                .get(&key)
                .into_iter()
                .flatten()
                .chain(
                    self.scheduler
                        .link_streams
                        .keys()
                        .filter(|(k, _)| *k == key)
                        .map(|(_, link)| link),
                )
                .collect();
            let mut links: Vec<String> = if excluded.is_empty() {
                Vec::new()
            } else {
                usable
                    .iter()
                    .filter(|l| !excluded.contains(l))
                    .cloned()
                    .collect()
            };
            if !excluded.is_empty() && links.is_empty() {
                // Nothing left to ask on this stream's links this round.
                self.scheduler.advance_continuous(&key, now);
                continue;
            }
            // RFC 6762 §7.3: another querier just asked the same QM
            // question with no KA we wouldn't send — treat ours as sent.
            // QU elicits unicast and is never suppressed. Overheard on one
            // of several links we'd ask, it stands in for ours there only.
            let scope = if qu {
                Some(links.clone())
            } else {
                self.overheard_scope(&key, &ka, &links)
            };
            let Some(scope) = scope else {
                log::debug!("mex: suppressed continuous query for {} (overheard)", key.0);
                let now = Instant::now();
                self.diagnostics.suppressed_continuous += 1;
                self.diagnostics.suppressed_times.push_back(now);
                self.note_query(&key.0, key.1, OwnQuery::Suppressed, now);
                self.route_own_question(&key.0, key.1, false);
                self.scheduler.advance_continuous(&key, now);
                continue;
            };
            links = scope;
            if qu {
                self.scheduler.startup_qu_sent = true;
                // Keep the flag for the passive-mode test; per-name QU above
                // no longer depends on it.
            }
            self.diagnostics.q_sent_continuous += 1;
            log::debug!(
                "mex: sending continuous query for {} (qu={})",
                send_name,
                qu
            );
            if qu {
                self.diagnostics.qu_sent += 1;
            }
            self.diagnostics.ka_sent += ka.len() as u64;
            self.queue_question(browse::QueryRequest {
                name: send_name.clone(),
                record_type: rt,
                known_answers: ka,
                qu,
                links,
            });
            self.route_own_question(&send_name, key.1, qu);
            // RFC 6762 §5.2: at least 1s between the first two, then at
            // least doubling, capped at one query per hour. Send using the
            // current interval, then double for the following gap, so the
            // stream is 1s, 2s, 4s, ... (doubling before use would skip
            // the 1s gap and start at 2s).
            self.scheduler.advance_continuous(&key, now);
        }
        self.poll_link_streams(now);
    }

    pub(super) fn send_queries(&mut self) {
        // Passive mode transmits nothing: no QU batch, no continuous
        // stream, no TTL refreshes. Filing received data and the link
        // refresh below still run.
        if !self.passive {
            // Learn service types before scheduling so new PTR owners are
            // browsed without waiting for a record-bearing service entry.
            // Lowercased: `_HTTP` and `_http` are the same type (RFC 6763 §7).
            for svc in &self.services {
                self.scheduler
                    .known_types
                    .insert(svc.service_type.to_ascii_lowercase());
            }
            for p in &self.pending_instances {
                self.scheduler
                    .known_types
                    .insert(p.service_type.to_ascii_lowercase());
            }
            for t in self.scheduler.enum_known.keys() {
                self.scheduler.known_types.insert(t.clone());
            }

            // While no family can transmit, queries would be queued and
            // dropped by the listener: hold both schedules instead, so
            // nothing is counted as sent, discovery doesn't back off, and
            // refresh attempts aren't used up (records still expire at
            // 100% TTL). When a family resumes, restart discovery with the
            // RFC 6762 §5.2 startup schedule, as for an interface coming
            // up: clearing the streams re-creates them through the normal
            // first-query path (20–120 ms jitter, dampening, startup QU).
            let can_transmit = self.query_tx.transmit().any();
            if !can_transmit {
                if !self.scheduler.transmit_held {
                    log::info!("mex: no family can transmit; queries on hold");
                }
                self.scheduler.transmit_held = true;
                // Keep the refresh bookkeeping honest without sending:
                // expired or replaced rows drop out, live rows keep their
                // attempts and next due time.
                self.update_refreshes(false);
            } else {
                if self.scheduler.transmit_held {
                    log::info!("mex: transmission resumed; restarting discovery");
                    self.scheduler.continuous.clear();
                    self.scheduler.covered.clear();
                    self.scheduler.transmit_held = false;
                    // Links just came back: take a fresh interface
                    // snapshot first, so resumed queries record the
                    // interfaces they really went out on.
                    self.refresh_link_snapshot();
                }
                self.requery_expiring();
                self.poll_continuous();
                self.flush_outbox();
            }
        }

        // Refresh in case interfaces/addresses changed (cheap: ~1 fork/min).
        // Independent of query backoff.
        if self.last_ip_refresh.elapsed() >= LOCAL_IPS_REFRESH {
            self.refresh_link_snapshot();
        }
    }

    /// Record an overheard QM question for duplicate question suppression
    /// (RFC 6762 §7.3). Own loopback and QU questions are never stored.
    /// The remote Known-Answer set is stored dot-trimmed and lowercased;
    /// the subset check runs at send time against the KA we would send.
    pub(super) fn note_overheard(&mut self, q: &browse::RawRecord, ev: &browse::Event) {
        if q.qu {
            return;
        }
        if self.is_local_source(&ev.source) {
            return;
        }
        self.scheduler.note_overheard(q, &ev.query_kas);
    }

    /// The known answers a scheduled query for `name` carries: PTR only
    /// (shared records, RFC 6762 §7.1), from the enumeration or the type.
    fn scheduled_known_answers(&self, name: &str, rt: TYPE) -> Vec<browse::KnownAnswer> {
        if rt != TYPE::PTR {
            Vec::new()
        } else if is_enum_name(name) {
            self.known_enum_answers()
        } else {
            self.known_ptrs(name)
        }
    }

    /// Where our query for `key` still goes after RFC 6762 §7.3 (#441):
    /// `links` are the links we'd ask (empty for every usable link). An
    /// overheard copy stands in for ours only on the link it came in on.
    /// On a link we don't ask it stands in for nothing: `links` unchanged,
    /// and the overheard entry is kept. On one of several links we ask,
    /// the others remain. On the only link we ask, or on an unknown link,
    /// it stands in everywhere: `None`, as before per-link suppression.
    pub(super) fn overheard_scope(
        &mut self,
        key: &(String, u16),
        ka: &[browse::KnownAnswer],
        links: &[String],
    ) -> Option<Vec<String>> {
        let asked: Vec<String> = if links.is_empty() {
            self.query_links().into_iter().collect()
        } else {
            links.to_vec()
        };
        let on = self.scheduler.overheard_link(key);
        if on.as_ref().is_some_and(|on| !asked.contains(on)) {
            return Some(links.to_vec());
        }
        if !self.scheduler.suppressed_by_overheard(key, ka) {
            return Some(links.to_vec());
        }
        match on {
            Some(on) if asked.len() > 1 => {
                log::debug!(
                    "mex: query for {} overheard on {on}; asking the other links",
                    key.0
                );
                Some(asked.into_iter().filter(|l| *l != on).collect())
            }
            _ => None,
        }
    }

    /// Follow the usable links since the last poll (#441). A link that
    /// went away is dropped from every stream's covered links, so it counts
    /// as new when it comes back. A new link (just up, newly selected, or
    /// back) starts a link stream for every question: the startup
    /// schedule on that link alone, so the other links keep theirs. The
    /// first poll only learns the links.
    fn follow_link_changes(
        &mut self,
        usable: &BTreeSet<String>,
        now: Instant,
        first_delay: &mut Option<Duration>,
    ) {
        for cover in self.scheduler.covered.values_mut() {
            cover.retain(|link| usable.contains(link));
        }
        let previous = std::mem::replace(&mut self.scheduler.last_usable, usable.clone());
        // Link streams end with their question, link or coverage.
        let (continuous, covered) = (&self.scheduler.continuous, &self.scheduler.covered);
        self.scheduler.link_streams.retain(|(key, link), _| {
            continuous.contains_key(key)
                && usable.contains(link)
                && !covered.get(key).is_some_and(|c| c.contains(link))
        });
        let new_links: Vec<String> = if previous.is_empty() {
            Vec::new()
        } else {
            usable.difference(&previous).cloned().collect()
        };
        if new_links.is_empty() {
            return;
        }
        log::info!(
            "mex: {} became usable; starting discovery there",
            new_links.join(", ")
        );
        let delay = *first_delay.get_or_insert_with(|| rand_range(20, 120));
        let keys: Vec<(String, u16)> = self.scheduler.continuous.keys().cloned().collect();
        for key in keys {
            for link in &new_links {
                self.scheduler.link_streams.insert(
                    (key.clone(), link.clone()),
                    LinkStream {
                        next_due: now + delay,
                        interval: Duration::from_secs(1),
                    },
                );
            }
        }
    }

    /// Ask the questions whose link streams are due (#441): each on its
    /// own link alone, §7.3-suppressed only by a query overheard there,
    /// then doubling; once its interval has caught up with the question's
    /// stream, the link joins that stream.
    fn poll_link_streams(&mut self, now: Instant) {
        type Due = ((String, u16), String, String, Duration, Duration);
        let due: Vec<Due> = self
            .scheduler
            .link_streams
            .iter()
            .filter(|(_, stream)| now >= stream.next_due)
            .filter_map(|((key, link), stream)| {
                let entry = self.scheduler.continuous.get(key)?;
                Some((
                    key.clone(),
                    link.clone(),
                    entry.qname.clone(),
                    stream.interval,
                    entry.interval,
                ))
            })
            .collect();
        for (key, link, qname, step, joins_at) in due {
            let Some(rt) = browse::record_type_from_u16(key.1) else {
                continue;
            };
            let ka = self.scheduled_known_answers(&key.0, rt);
            match self.overheard_scope(&key, &ka, std::slice::from_ref(&link)) {
                None => {
                    self.diagnostics.suppressed_continuous += 1;
                    self.diagnostics.suppressed_times.push_back(now);
                    self.note_query_on(
                        &key.0,
                        key.1,
                        OwnQuery::Suppressed,
                        now,
                        std::slice::from_ref(&link),
                    );
                }
                Some(links) => {
                    self.diagnostics.q_sent_continuous += 1;
                    self.diagnostics.ka_sent += ka.len() as u64;
                    self.queue_question(browse::QueryRequest {
                        name: qname.clone(),
                        record_type: rt,
                        known_answers: ka,
                        qu: false,
                        links,
                    });
                }
            }
            self.route_own_question(&qname, key.1, false);
            // Send using the current interval, then double (RFC 6762 §5.2);
            // caught up with the question's stream, the link joins it.
            let next = (step * 2).min(MAX_CONTINUOUS_INTERVAL);
            if next >= joins_at {
                self.scheduler.link_streams.remove(&(key, link));
            } else {
                self.scheduler.link_streams.insert(
                    (key, link),
                    LinkStream {
                        next_due: now + step,
                        interval: next,
                    },
                );
            }
        }
    }

    /// The usable links queries go out on: interface names of both
    /// families, within the `-i` selection.
    pub(super) fn query_links(&self) -> BTreeSet<String> {
        self.link_stats
            .v4
            .iter()
            .map(|(name, _)| name.clone())
            .chain(self.link_stats.v6.iter().map(|(name, _)| name.clone()))
            .filter(|name| {
                self.interfaces
                    .as_ref()
                    .is_none_or(|selected| selected.contains(name))
            })
            .collect()
    }

    /// The link (interface name) `rec` arrived on, as `query_links` names
    /// it: its resolved name, else the IPv6 link with its index. `None`
    /// when neither is known.
    pub(super) fn answer_link(&self, rec: &browse::RawRecord) -> Option<String> {
        if !rec.iface.is_empty() {
            return Some(rec.iface.clone());
        }
        self.link_stats
            .v6
            .iter()
            .find(|(_, idx)| *idx == rec.ifindex && rec.ifindex != 0)
            .map(|(name, _)| name.clone())
    }

    /// The links fresh unique answers for `key` arrived on (#441), and
    /// whether one came on an unknown link (which then covers them all,
    /// as before per-link dampening).
    pub(super) fn fresh_unique_cover(&self, key: &(String, u16)) -> (bool, BTreeSet<String>) {
        let mut unknown = false;
        let mut cover = BTreeSet::new();
        for r in self.fresh_unique_answers(key) {
            match self.answer_link(r) {
                Some(link) => {
                    cover.insert(link);
                }
                None => unknown = true,
            }
        }
        (unknown, cover)
    }

    /// Whether a live unique answer (`is_unique_answer`) for `key` is
    /// cached and still before its 80%-TTL refresh window. Scheduling reads
    /// the links of those answers (`fresh_unique_cover`); this is the
    /// tests' yes/no view.
    #[cfg(test)]
    pub(super) fn has_fresh_unique_answer(&self, key: &(String, u16)) -> bool {
        self.fresh_unique_answers(key).next().is_some()
    }

    /// The live unique answers for `key` still before their 80%-TTL
    /// refresh window.
    fn fresh_unique_answers<'s>(
        &'s self,
        key: &'s (String, u16),
    ) -> impl Iterator<Item = &'s browse::RawRecord> + 's {
        // Pending instances count too: they already drive SRV/TXT
        // interest (`desired_continuous`) before their SRV arrives.
        self.services
            .iter()
            .flat_map(|s| &s.answers)
            .chain(self.pending_instances.iter().flat_map(|p| &p.answers))
            .filter(move |r| {
                if !is_unique_answer(r)
                    || r.ttl == 0
                    || r.rtype != key.1
                    || r.name.trim_end_matches('.').to_ascii_lowercase() != key.0
                {
                    return false;
                }
                let elapsed = r.received_at.elapsed().as_secs() as u32;
                !in_refresh_window(elapsed, r.ttl)
            })
    }
}
