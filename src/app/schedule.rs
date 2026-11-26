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

    /// Record our own transmit or suppression for an interest, with the
    /// links a transmit went out on.
    pub(super) fn note_query(
        &mut self,
        name: &str,
        rtype: u16,
        origin: QueryOrigin,
        at: Instant,
        interfaces: String,
    ) {
        let entry = self
            .query_history
            .entry(Self::provenance_key(name, rtype))
            .or_default();
        match origin {
            QueryOrigin::Transmitted => {
                entry.transmitted = Some(at);
                entry.transmitted_interfaces = interfaces;
            }
            QueryOrigin::Suppressed => entry.suppressed = Some(at),
            QueryOrigin::Observed => {
                // Observed questions carry their own packet timestamp
                // and source; use `note_observed` instead.
            }
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
        if self.scheduler.suppressed_by_overheard(key, &ka) {
            log::debug!("mex: suppressed refresh query for {} (overheard)", key.0);
            self.diagnostics.suppressed_refresh += 1;
            self.diagnostics.suppressed_times.push_back(now);
            self.note_query(&key.0, key.1, QueryOrigin::Suppressed, now);
        } else {
            self.diagnostics.q_sent_refresh += 1;
            self.diagnostics.ka_sent += ka.len() as u64;
            if self.query_tx.send(browse::QueryRequest {
                name: key.0.clone(),
                record_type: rt,
                known_answers: ka,
                qu: false,
            }) {
                self.note_query(&key.0, key.1, QueryOrigin::Transmitted, now);
            } else {
                log::warn!(
                    "mex: dropped refresh query for {} (listener channels closed)",
                    key.0
                );
            }
        }
        self.route_own_question(&key.0, key.1, false);
        // A refresh query also elicits new answers, so postpone the
        // exponential stream for the same question: otherwise the two
        // timers can fire on the same tick and emit back-to-back
        // duplicates (RFC 6762 §5.2 spacing).
        self.scheduler.postpone_continuous_for_refresh(key, now);
        true
    }

    /// Record a query event for an interest: we transmitted it or §7.3
    /// suppression stood in for it, stamped at action time.
    pub(super) fn note_query(&mut self, name: &str, rtype: u16, origin: QueryOrigin, at: Instant) {
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
                    let (next_due, interval) = if self.has_fresh_unique_answer(&key) {
                        self.route_own_question(&qname, key.1, false);
                        (now + MAX_CONTINUOUS_INTERVAL, MAX_CONTINUOUS_INTERVAL)
                    } else {
                        (now + rand_range(20, 120), Duration::from_secs(1))
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
            let ka = if rt == TYPE::PTR {
                if is_enum_name(&key.0) {
                    self.known_enum_answers()
                } else {
                    self.known_ptrs(&key.0)
                }
            } else {
                Vec::new()
            };
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
            // RFC 6762 §7.3: another querier just asked the same QM
            // question with no KA we wouldn't send — treat ours as sent.
            // QU elicits unicast and is never suppressed.
            if !qu && self.scheduler.suppressed_by_overheard(&key, &ka) {
                log::debug!("mex: suppressed continuous query for {} (overheard)", key.0);
                let now = Instant::now();
                self.diagnostics.suppressed_continuous += 1;
                self.diagnostics.suppressed_times.push_back(now);
                self.note_query(&key.0, key.1, QueryOrigin::Suppressed, now);
                self.route_own_question(&key.0, key.1, false);
                self.scheduler.advance_continuous(&key, now);
                continue;
            }
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
            if self.query_tx.send(browse::QueryRequest {
                name: send_name.clone(),
                record_type: rt,
                known_answers: ka,
                qu,
            }) {
                self.note_query(&send_name, key.1, QueryOrigin::Transmitted, now);
            } else {
                log::warn!(
                    "mex: dropped continuous query for {} (listener channels closed)",
                    send_name
                );
            }
            self.route_own_question(&send_name, key.1, qu);
            // RFC 6762 §5.2: at least 1s between the first two, then at
            // least doubling, capped at one query per hour. Send using the
            // current interval, then double for the following gap, so the
            // stream is 1s, 2s, 4s, ... (doubling before use would skip
            // the 1s gap and start at 2s).
            self.scheduler.advance_continuous(&key, now);
        }
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
                    self.scheduler.transmit_held = false;
                    // Links just came back: take a fresh interface
                    // snapshot first, so resumed queries record the
                    // interfaces they really went out on.
                    self.refresh_link_snapshot();
                }
                self.requery_expiring();
                self.poll_continuous();
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

    /// Advance the exponential stream as if a query had been sent (shared
    /// by real sends and §7.3 suppression).
    /// Whether a live unique (cache-flush) answer for `key` is cached and
    /// still before its 80%-TTL refresh window.
    pub(super) fn has_fresh_unique_answer(&self, key: &(String, u16)) -> bool {
        // Pending instances count too: they already drive SRV/TXT
        // interest (`desired_continuous`) before their SRV arrives.
        let mut rows = self
            .services
            .iter()
            .flat_map(|s| &s.answers)
            .chain(self.pending_instances.iter().flat_map(|p| &p.answers));
        rows.any(|r| {
            if !r.flush_bit
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
