// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    pub(super) fn ingest_event(&mut self, ev: &browse::Event) {
        self.touch();
        // RFC 6762 §18.3: a message with a non-zero OPCODE, query or
        // response, MUST be silently ignored. The raw packet stays in the
        // packet log for inspection, but none of its records or questions
        // reach state. Checked first, so one with a non-zero RCODE as well
        // is still counted, and the overlay shows something sends them.
        if ev.is_ignored() {
            log::debug!(
                "mex: ignoring message from {} with OPCODE {}",
                ev.source,
                ev.opcode()
            );
            self.diagnostics.opcode_ignored += 1;
            self.diagnostics.opcode_ignored_last = Some((ev.source, Instant::now()));
            return;
        }
        // RFC 6762 §18.11: likewise for a response with a non-zero RCODE.
        if has_nonzero_rcode(ev) {
            log::debug!(
                "mex: ignoring response from {} with RCODE {:?}",
                ev.source,
                ev.rcode
            );
            return;
        }
        log::trace!(
            "mex: ingesting packet from {} ({} answer(s), {} question(s))",
            ev.source,
            ev.answers.len(),
            ev.questions.len()
        );
        // Denials first: the filing gate then keeps this packet's own
        // address additionals off a denying service, with no side effects
        // (e.g. cache-flush damping) for rows it never keeps.
        self.ingest_address_denials(ev);
        // NSEC rows go last, so an NSEC placed before its SRV in the
        // packet still finds the service that SRV creates.
        let (others, nsecs): (Vec<_>, Vec<_>) = ev.answers.iter().partition(|r| r.rtype != 47);
        for rec in others.into_iter().chain(nsecs) {
            // Out-of-scope types never become rows: they are kept only as
            // sightings behind findings, goodbyes included.
            if !anomalies::is_mdns_answer_type(rec.rtype) {
                // Remember the question that most likely triggered the
                // record, so findings can tell a reply to our own query
                // from one to someone else's.
                let mut rec = rec.clone();
                rec.trigger = self.scheduler.response_trigger(&rec);
                self.ingest_sighting(SightingKind::Response, rec);
                continue;
            }
            if rec.ttl == 0 {
                self.mark_goodbye(rec);
                self.ingest_goodbye(rec, ev);
                continue;
            }
            self.ingest_record(rec, ev);
        }
        for q in &ev.questions {
            if !anomalies::is_mdns_question_type(q.rtype) {
                // Provenance still notes the ask, so a response it
                // triggers can name it.
                self.scheduler.note_observed(q, ev.source);
                self.ingest_sighting(SightingKind::Question, q.clone());
                continue;
            }
            self.note_overheard(q, ev);
            self.route_question(q, ev);
        }
        // Out-of-scope known answers are beliefs, not facts, but still
        // out-of-scope data on the wire: sighted, never filed as rows.
        for ka in &ev.query_kas {
            if !anomalies::is_mdns_answer_type(ka.rtype) {
                self.ingest_sighting(SightingKind::KnownAnswer, ka.clone());
            }
        }
    }

    /// Lowercased keys of every live and pending service instance.
    pub(super) fn live_service_keys(&self) -> HashSet<String> {
        self.services
            .iter()
            .map(|s| service_key(&s.instance, &s.service_type))
            .chain(
                self.pending_instances
                    .iter()
                    .map(|p| service_key(&p.instance, &p.service_type)),
            )
            .collect()
    }

    /// File a goodbye (TTL 0) record with the matching service so it renders
    /// as an expired row instead of vanishing silently. PTR goodbyes name
    /// the type, so the withdrawn instance is matched via the rdata.
    pub(super) fn ingest_goodbye(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        if is_enum_name(rec.name.trim_end_matches('.')) {
            if let Some(entry) = self
                .enum_entries
                .iter_mut()
                .find(|e| e.name.eq_ignore_ascii_case(rec.name.trim_end_matches('.')))
            {
                entry.last_seen = Instant::now();
                entry.last_event = Some(ev.clone());
                // DNS names compare case-insensitively (RFC 6763 §7): a
                // peer varying the wire case must refresh the row, not
                // grow the list.
                if let Some(pos) = entry.answers.iter().position(|r| {
                    r.name.eq_ignore_ascii_case(&rec.name)
                        && r.rtype == rec.rtype
                        && same_ptr_target(r, rec)
                        && r.source == rec.source
                        && r.ifindex == rec.ifindex
                }) {
                    entry.answers[pos] = rec.clone();
                } else {
                    entry.answers.push(rec.clone());
                }
            }
            return;
        }
        // An address still waiting for its service is withdrawn too: the
        // same (type, rdata, source) identity `handle_addr` updates by,
        // so a responder only withdraws its own announcement.
        if matches!(rec.rtype, 1 | 28) {
            let host = rec.name.trim_end_matches('.').to_ascii_lowercase();
            if let Some(records) = self.pending_addrs.get_mut(&host) {
                for pending in records.iter_mut().filter(|p| {
                    p.rtype == rec.rtype
                        && p.rdata == rec.rdata
                        && p.source == rec.source
                        && p.ifindex == rec.ifindex
                }) {
                    *pending = rec.clone();
                }
            }
        }
        let mut names = vec![rec.name.trim_end_matches('.').to_ascii_lowercase()];
        if rec.rtype == 12 {
            names.push(rec.rdata.trim_end_matches('.').to_ascii_lowercase());
        }
        // One hostname backs many services: file the goodbye on every
        // match (notably TTL 0 A/AAAA) instead of stopping at the first.
        let mut hits = Vec::new();
        for (i, svc) in self.services.iter().enumerate() {
            let full =
                crate::browse::instance_name(&svc.instance, &svc.service_type).to_ascii_lowercase();
            let host = svc.hostname.trim_end_matches('.').to_ascii_lowercase();
            let inst = browse::escape_label(&svc.instance).to_ascii_lowercase();
            let alternate = svc.answers.iter().any(|r| {
                if r.rtype != 33 {
                    return false;
                }
                if r.ttl <= r.received_at.elapsed().as_secs() as u32 {
                    return false;
                }
                let target = r
                    .rdata
                    .splitn(4, ' ')
                    .nth(3)
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                names.contains(&target)
            });
            if names.iter().any(|n| *n == full || *n == host || *n == inst) || alternate {
                hits.push(i);
            }
        }
        for i in hits {
            self.services[i].last_event = Some(ev.clone());
            self.push_record(i, rec);
        }
    }

    pub(super) fn ingest_record(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        log::trace!(
            "mex: ingesting {} record {} from {}",
            rec.rtype_str,
            rec.name,
            ev.source
        );
        match rec.rtype {
            12 => self.handle_ptr(rec, ev),
            33 => self.handle_srv(rec, ev),
            16 => self.handle_txt(rec, ev),
            1 | 28 => self.handle_addr(rec, ev),
            _ => self.handle_other(rec, ev),
        }
    }

    pub(super) fn handle_ptr(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let st = rec.name.trim_end_matches('.');
        let target = rec.rdata.trim_end_matches('.');

        if is_enum_name(st) {
            // Track enumeration answers for known-answer suppression and
            // for the continuous browse set; polling itself runs through
            // the §5.2 backoff in poll_continuous. Keys are lowercased so
            // `_HTTP` and `_http` announcements coalesce (RFC 6763 §7).
            // The full answer is also filed on the selectable enumeration
            // row so the Answers pane shows what each link advertises.
            self.scheduler.note_enum_type(target, rec);
            if let Some(entry) = self
                .enum_entries
                .iter_mut()
                .find(|e| e.name.eq_ignore_ascii_case(st))
            {
                entry.last_seen = Instant::now();
                entry.last_event = Some(ev.clone());
                // DNS names compare case-insensitively (RFC 6763 §7): a
                // peer varying the wire case must refresh the row, not
                // grow the list.
                if let Some(pos) = entry.answers.iter().position(|r| {
                    r.name.eq_ignore_ascii_case(&rec.name)
                        && r.rtype == rec.rtype
                        && same_ptr_target(r, rec)
                        && r.source == rec.source
                        && r.ifindex == rec.ifindex
                }) {
                    entry.answers[pos] = rec.clone();
                } else {
                    entry.answers.push(rec.clone());
                }
                // A fresh answer resets the requery schedule unless a
                // sibling row is still inside its 80%-TTL window.
                let key = (rec.name.trim_end_matches('.').to_string(), rec.rtype);
                let still_expiring = entry.answers.iter().any(|r| {
                    if r.ttl == 0
                        || r.name.trim_end_matches('.') != key.0.as_str()
                        || r.rtype != key.1
                    {
                        return false;
                    }
                    let elapsed = r.received_at.elapsed().as_secs() as u32;
                    elapsed <= r.ttl && in_refresh_window(elapsed, r.ttl)
                });
                if !still_expiring {
                    self.scheduler.refresh_answered(&key);
                }
            }
            return;
        }

        // Reverse-mapping PTRs (in-addr.arpa / ip6.arpa) map addresses to
        // hostnames; they are not service enumeration and must not seed
        // pending services (which check_type_format would then flag).
        if crate::anomalies::is_reverse_ptr(st) {
            return;
        }

        if let Some((subtype, svc_type)) = subtype_owner_parts(rec) {
            let (instance, svc_type) = Self::ptr_instance(rec, target, &svc_type);
            let instance = &instance;
            // Late subtype PTRs (arriving after the SRV already promoted
            // the service, the normal passive-mode order) land on the live
            // service directly; otherwise they wait in pending for the SRV
            // merge. Touching pending when the service exists strands a
            // duplicate entry that only expires via the grace timeout.
            if let Some(idx) = self.services.iter().position(|s| {
                s.instance.eq_ignore_ascii_case(instance)
                    && s.service_type.eq_ignore_ascii_case(&svc_type)
            }) {
                if !self.services[idx]
                    .subtypes
                    .iter()
                    .any(|s| s.as_slice().eq_ignore_ascii_case(&subtype))
                {
                    self.services[idx].subtypes.push(subtype);
                }
                self.services[idx].last_event = Some(ev.clone());
                self.push_record(idx, rec);
                return;
            }
            let pi = self.ensure_pending(instance, &svc_type);
            if !self.pending_instances[pi]
                .subtypes
                .iter()
                .any(|s| s.as_slice().eq_ignore_ascii_case(&subtype))
            {
                self.pending_instances[pi].subtypes.push(subtype);
            }
            self.pending_instances[pi].answers.push(rec.clone());
            return;
        }

        let (instance, st) = Self::ptr_instance(rec, target, st);
        let (instance, st) = (instance.as_str(), st.as_str());
        // A PTR for an already-confirmed service (SRV first, the passive
        // order) lands on that service only, like late TXT and subtype
        // PTRs. A pending copy here would be refreshed by every later PTR
        // and only absorbed by the next SRV. It must still reactivate the
        // service: after a goodbye the service is inactive, and push_record
        // reactivates on a live PTR (SRV/TXT answers still cannot resurrect
        // a withdrawn service).
        if let Some(idx) = self.services.iter().position(|s| {
            s.instance.eq_ignore_ascii_case(instance) && s.service_type.eq_ignore_ascii_case(st)
        }) {
            self.services[idx].last_event = Some(ev.clone());
            self.push_record(idx, rec);
            return;
        }
        let pi = self.ensure_pending(instance, st);
        self.pending_instances[pi].answers.push(rec.clone());
    }

    /// (instance, service type) a PTR target names under the browsed
    /// `svc_type`. Instances are kept as plain label text; the target is in
    /// presentation form. One label before `svc_type` is the instance. More
    /// labels there name an instance of a deeper type, so the target splits
    /// like an SRV owner, first wire label as the instance: read as one
    /// label, `a.b` would be the dotted instance `a\.b` (#386). A target
    /// outside `svc_type` stays its instance, as it always has.
    pub(super) fn ptr_instance(
        rec: &browse::RawRecord,
        target: &str,
        svc_type: &str,
    ) -> (String, String) {
        let Some(prefix) = Self::strip_suffix_ci(target, svc_type) else {
            return (browse::unescape_name(target), svc_type.to_string());
        };
        let mut labels = browse::presentation_labels(prefix);
        if labels.len() == 1 {
            return (labels.remove(0), svc_type.to_string());
        }
        let labels = match rec.ptr_target_labels.as_deref() {
            Some(wire) => wire
                .iter()
                .map(|label| String::from_utf8_lossy(label).into_owned())
                .collect(),
            None => browse::presentation_labels(target),
        };
        // Wire labels that disagree with the target name (never from the
        // parser) leave the target whole, as for a target outside the type.
        let (instance, service_type) = match labels.as_slice() {
            [instance, service_type @ ..] if !service_type.is_empty() => (instance, service_type),
            _ => return (browse::unescape_name(target), svc_type.to_string()),
        };
        let service_type = service_type
            .iter()
            .map(|label| browse::escape_label(label))
            .collect::<Vec<_>>()
            .join(".");
        (instance.clone(), service_type)
    }

    /// Split an SRV/TXT owner into (instance, service type). The wire
    /// labels are exact: the instance is the first label (RFC 6763 §4.1),
    /// even when it holds dots (`Á.a._test._tcp.local`). The instance is
    /// the plain label text; the type is in presentation form, like the
    /// record names it is matched against. Without wire labels, the
    /// presentation-form owner name splits at its first unescaped dot,
    /// unless a known service type matches first.
    pub(super) fn split_owner(&self, rec: &browse::RawRecord) -> Option<(String, String)> {
        if let [instance, service_type @ ..] = rec.owner_labels.as_slice() {
            if service_type.is_empty() {
                return None;
            }
            let service_type = service_type
                .iter()
                .map(|label| browse::escape_label(&String::from_utf8_lossy(label)))
                .collect::<Vec<_>>()
                .join(".");
            return Some((String::from_utf8_lossy(instance).into_owned(), service_type));
        }
        let name = rec.name.trim_end_matches('.');
        self.split_instance_type(name).or_else(|| {
            let mut labels = browse::presentation_labels(name).into_iter();
            let instance = labels.next()?;
            let service_type = labels
                .map(|label| browse::escape_label(&label))
                .collect::<Vec<_>>()
                .join(".");
            (!service_type.is_empty()).then_some((instance, service_type))
        })
    }

    /// Split a full instance name ("inst._svc._tcp.local") into (instance,
    /// service type). Instance names may legally contain dots (e.g. Fire TV
    /// style "amzn.dmgr:...:..."), so splitting on the first dot misparses
    /// them. Match against known service types instead (longest suffix
    /// wins, case-insensitively per RFC 6763 §7); the caller falls back to
    /// the naive split when nothing is known yet. Both parts keep wire
    /// case; callers compare case-insensitively.
    pub(super) fn split_instance_type(&self, full_name: &str) -> Option<(String, String)> {
        let mut best: Option<(String, String)> = None;
        let mut consider = |known: &str| {
            if known.is_empty() {
                return;
            }
            if full_name.len() <= known.len() {
                return;
            }
            // Instance names may hold multi-byte UTF-8 (RFC 6763 §4.1.1):
            // skip offsets landing inside a character instead of panicking
            // in `split_at` (e.g. `é._ssh._tcp.local` vs `_https._tcp.local`).
            let off = full_name.len() - known.len();
            if !full_name.is_char_boundary(off) {
                return;
            }
            let (prefix, tail) = full_name.split_at(off);
            if !tail.eq_ignore_ascii_case(known) {
                return;
            }
            let Some(instance) = prefix.strip_suffix('.') else {
                return;
            };
            // An escaped dot (`\.`) is inside the instance label, and the
            // instance is one label: `a.b` before a known type is no
            // instance of it (that would be the dotted `a\.b`, #386).
            if instance.is_empty()
                || browse::escapes_next(instance)
                || browse::presentation_labels(instance).len() != 1
            {
                return;
            }
            let replace = match &best {
                Some((_, current)) => known.len() > current.len(),
                None => true,
            };
            if replace {
                best = Some((browse::unescape_name(instance), tail.to_string()));
            }
        };
        for s in &self.services {
            consider(&s.service_type);
        }
        for p in &self.pending_instances {
            consider(&p.service_type);
        }
        for t in self.scheduler.type_names() {
            consider(t);
        }
        best
    }

    pub(super) fn handle_srv(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let Some((instance, service_type)) = self.split_owner(rec) else {
            return;
        };
        let idx = self.ensure_svc(&instance, &service_type);

        let sv: Vec<&str> = rec.rdata.split_whitespace().collect();
        if sv.len() >= 4 {
            let new_host = rec
                .rdata
                .splitn(4, ' ')
                .nth(3)
                .unwrap_or("")
                .trim()
                .to_string();
            // Keep a host name stable when several SRVs for the same
            // instance advertise different targets (e.g. a device reachable
            // under both a `.local` and a unicast name): once both targets
            // are known, a refresh of either must not flip the host grouping
            // back and forth. A genuinely new target (one never seen before
            // for this instance) still moves the service, and an expired
            // current host gives way to whatever is live.
            let current_host = self.services[idx].hostname.clone();
            let current_norm = current_host.trim_end_matches('.').to_ascii_lowercase();
            let new_norm = new_host.trim_end_matches('.').to_ascii_lowercase();
            let update = if current_host.is_empty() || current_norm == new_norm {
                true
            } else {
                let current_live = self.services[idx].answers.iter().any(|r| {
                    if r.rtype != 33 {
                        return false;
                    }
                    let target = r
                        .rdata
                        .splitn(4, ' ')
                        .nth(3)
                        .unwrap_or("")
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    target == current_norm && r.ttl > r.received_at.elapsed().as_secs() as u32
                });
                let target_known = self.services[idx].answers.iter().any(|r| {
                    if r.rtype != 33 {
                        return false;
                    }
                    let target = r
                        .rdata
                        .splitn(4, ' ')
                        .nth(3)
                        .unwrap_or("")
                        .trim()
                        .trim_end_matches('.')
                        .to_ascii_lowercase();
                    target == new_norm && r.ttl > r.received_at.elapsed().as_secs() as u32
                });
                !current_live || !target_known
            };
            if update {
                self.services[idx].port = sv[2].parse().unwrap_or(0);
                self.services[idx].hostname = new_host;
            }
        }
        self.push_record(idx, rec);
        self.services[idx].last_event = Some(ev.clone());
        // A service promoted after its host's address arrived would miss
        // it until the next announcement (several SRVs, one host):
        // backfill live A/AAAA rows already held by siblings. Cloning is
        // idempotent (push_record dedups by name/type/rdata/source) and
        // keeps the original receipt time, so TTL aging stays consistent.
        let host_key = self.services[idx]
            .hostname
            .trim_end_matches('.')
            .to_ascii_lowercase();
        if !host_key.is_empty() {
            let mut backfill = Vec::new();
            for (si, svc) in self.services.iter().enumerate() {
                if si == idx {
                    continue;
                }
                if svc.hostname.trim_end_matches('.').to_ascii_lowercase() != host_key {
                    continue;
                }
                for r in &svc.answers {
                    // Owner check, not just sibling check: a sibling that
                    // moved SRV targets keeps its old-host rows, and those
                    // must not leak onto this host. Names compare
                    // case-insensitively (RFC 6763 §7).
                    if (r.rtype == 1 || r.rtype == 28)
                        && r.name.trim_end_matches('.').to_ascii_lowercase() == host_key
                        && r.ttl > r.received_at.elapsed().as_secs() as u32
                    {
                        backfill.push(r.clone());
                    }
                }
            }
            // Addresses withheld from every other service (all deny them)
            // are still live addresses of this host.
            let withheld: Vec<browse::RawRecord> = self
                .address_denials
                .withheld(&host_key)
                .filter(|r| r.ttl > r.received_at.elapsed().as_secs() as u32)
                .cloned()
                .collect();
            for r in backfill.iter().chain(&withheld) {
                self.push_record(idx, r);
            }
            // A cached copy filed on a sibling is not a network update: the
            // host keeps its own copy (the sibling may go away while the
            // others still deny the family).
            for r in &withheld {
                self.address_denials.withhold(r);
            }
        }

        // merge any cached data from pending_instances, routing each
        // record through push_record so live PTRs reactivate a returned
        // service (and replace their goodbye rows) instead of duplicating
        // them via a blind extend.
        let svc_idx = idx;
        let mut i = 0;
        while i < self.pending_instances.len() {
            if self.pending_instances[i]
                .instance
                .eq_ignore_ascii_case(&instance)
                && self.pending_instances[i]
                    .service_type
                    .eq_ignore_ascii_case(&service_type)
            {
                let p = self.pending_instances.swap_remove(i);
                for sub in p.subtypes {
                    if !self.services[svc_idx]
                        .subtypes
                        .iter()
                        .any(|s| s.as_slice().eq_ignore_ascii_case(&sub))
                    {
                        self.services[svc_idx].subtypes.push(sub);
                    }
                }
                for q in p.questions {
                    let svc = &mut self.services[svc_idx];
                    Self::file_question_counted(
                        &mut svc.questions,
                        &mut svc.questions_dropped,
                        q.0,
                        q.1,
                        q.2,
                        q.3,
                        q.4,
                    );
                }
                // Evicted pending rows never reappear: carry the count so
                // the dump still marks the promoted list as truncated.
                self.services[svc_idx].questions_dropped += p.questions_dropped;
                self.services[svc_idx].last_seen =
                    self.services[svc_idx].last_seen.max(p.last_seen);
                let answers = p.answers;
                for rec in &answers {
                    self.push_record(svc_idx, rec);
                }
            } else {
                i += 1;
            }
        }
    }

    pub(super) fn handle_txt(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let Some((instance, service_type)) = self.split_owner(rec) else {
            return;
        };
        // Late TXT (arriving after the SRV already promoted the service,
        // the normal passive-mode order) lands on the live service
        // directly; otherwise it waits in pending for the SRV merge.
        if let Some(idx) = self.services.iter().position(|s| {
            s.instance.eq_ignore_ascii_case(&instance)
                && s.service_type.eq_ignore_ascii_case(&service_type)
        }) {
            self.services[idx].last_event = Some(ev.clone());
            self.push_record(idx, rec);
            return;
        }
        let pi = self.ensure_pending(&instance, &service_type);

        self.pending_instances[pi].answers.push(rec.clone());
        // The pending instance already drives the TXT stream: a TXT
        // arriving before its SRV answers it too (#438).
        self.dampen_if_unique(rec);
    }

    /// RFC 6762 §5.2: a unique answer (`is_unique_answer`: cache-flush
    /// bit, or a type unique by definition) means no other answers are
    /// forthcoming, so dampen its question's exponential discovery stream
    /// and let the 80%-TTL refresh take over. Only a fresh answer does,
    /// as at stream creation (`has_fresh_unique_answer`): a goodbye, or a
    /// row that expired or reached its refresh window while it waited on a
    /// pending instance, leaves the stream asking, since the refresh won't
    /// maintain it.
    fn dampen_if_unique(&mut self, rec: &browse::RawRecord) {
        let elapsed = rec.received_at.elapsed().as_secs() as u32;
        let fresh = rec.ttl > 0 && elapsed < rec.ttl && !in_refresh_window(elapsed, rec.ttl);
        if fresh && is_unique_answer(rec) {
            let ckey = Scheduler::continuous_key(rec.name.trim_end_matches('.'), rec.rtype);
            self.scheduler.dampen(&ckey);
        }
    }

    pub(super) fn handle_addr(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let host = rec.name.trim_end_matches('.').to_ascii_lowercase();
        // One hostname backs many services (several SRVs, one host):
        // file on every match, not just the first. A service may also be
        // reachable under alternate SRV targets, so route addresses for any
        // live target of the service, not only the selected hostname.
        let mut hits = Vec::new();
        for (i, svc) in self.services.iter().enumerate() {
            let selected = svc.hostname.trim_end_matches('.').to_ascii_lowercase() == host;
            let alternate = svc.answers.iter().any(|r| {
                r.rtype == 33
                    && r.ttl > r.received_at.elapsed().as_secs() as u32
                    && srv_target(&r.rdata).is_some_and(|target| target.eq_ignore_ascii_case(&host))
            });
            if selected || alternate {
                hits.push(i);
            }
        }
        if hits.is_empty() {
            let records = self.pending_addrs.entry(host).or_default();
            if let Some(pending) = records.iter_mut().find(|pending| {
                pending.rtype == rec.rtype
                    && pending.rdata == rec.rdata
                    && pending.source == rec.source
                    && pending.ifindex == rec.ifindex
            }) {
                *pending = rec.clone();
            } else {
                records.push(rec.clone());
            }
            return;
        }
        for i in hits {
            self.services[i].last_event = Some(ev.clone());
            self.push_record(i, rec);
        }
    }

    /// In-scope records other than PTR/SRV/TXT/A/AAAA (NS, CNAME,
    /// HINFO, NSEC). One hostname backs many services: a host-owned
    /// record (e.g. HINFO) files on every service of that host, like
    /// addresses, not just the first.
    pub(super) fn handle_other(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let name = rec.name.trim_end_matches('.').to_ascii_lowercase();
        let hits: Vec<usize> = self
            .services
            .iter()
            .enumerate()
            .filter(|(_, svc)| {
                // Instance name, selected hostname, or any live SRV target
                // (alternate targets own host records too, as for
                // addresses).
                crate::browse::instance_name(&svc.instance, &svc.service_type).to_ascii_lowercase()
                    == name
                    || svc.hostname.trim_end_matches('.').to_ascii_lowercase() == name
                    || Self::service_hosts(svc).contains(&name)
            })
            .map(|(i, _)| i)
            .collect();
        for i in hits {
            self.services[i].last_event = Some(ev.clone());
            self.push_record(i, rec);
        }
        // An instance NSEC before the SRV: keep it on the pending
        // instance, which hands its rows over on promotion.
        if rec.rtype == 47 {
            for p in &mut self.pending_instances {
                let full =
                    crate::browse::instance_name(&p.instance, &p.service_type).to_ascii_lowercase();
                if full != name {
                    continue;
                }
                p.answers.retain(|r| {
                    !(r.rtype == rec.rtype
                        && r.name.eq_ignore_ascii_case(&rec.name)
                        && r.source == rec.source
                        && r.ifindex == rec.ifindex)
                });
                p.answers.push(rec.clone());
                p.last_seen = Instant::now();
            }
        }
    }

    pub(super) fn ensure_pending(&mut self, instance: &str, service_type: &str) -> usize {
        for (i, p) in self.pending_instances.iter().enumerate() {
            if p.instance.eq_ignore_ascii_case(instance)
                && p.service_type.eq_ignore_ascii_case(service_type)
            {
                self.pending_instances[i].last_seen = Instant::now();
                return i;
            }
        }
        let i = self.pending_instances.len();
        self.pending_instances.push(PendingService {
            instance: instance.to_string(),
            service_type: service_type.to_string(),
            answers: Vec::new(),
            subtypes: Vec::new(),
            questions: Vec::new(),
            questions_dropped: 0,
            last_seen: Instant::now(),
        });
        i
    }

    pub(super) fn ensure_svc(&mut self, instance: &str, service_type: &str) -> usize {
        let now = Instant::now();
        for (i, s) in self.services.iter().enumerate() {
            if s.instance.eq_ignore_ascii_case(instance)
                && s.service_type.eq_ignore_ascii_case(service_type)
            {
                self.services[i].last_seen = now;
                return i;
            }
        }
        self.services.push(ServiceEntry {
            instance: instance.to_string(),
            service_type: service_type.to_string(),
            hostname: String::new(),
            port: 0,
            subtypes: Vec::new(),
            answers: Vec::new(),
            questions: Vec::new(),
            questions_dropped: 0,
            last_seen: now,
            is_active: true,
            last_event: None,
        });
        self.diagnostics.services_seen_total += 1;
        self.services.len() - 1
    }

    pub(super) fn push_record(&mut self, svc_idx: usize, rec: &browse::RawRecord) {
        // A denied address type stays off this service (#245); the host
        // header still lists it.
        let key = service_key(
            &self.services[svc_idx].instance,
            &self.services[svc_idx].service_type,
        );
        if self.address_denials.denies(&key, rec) {
            self.address_denials.withhold(rec);
            return;
        }
        // Filed normally: the service row is now the record's truth, so a
        // withheld copy (from before a denial lifted) must not outlive a
        // later goodbye or rdata change.
        if matches!(rec.rtype, 1 | 28) {
            self.address_denials.forget_withheld(rec);
        }
        let s = &mut self.services[svc_idx];
        // Host addresses are not signs of service life: filing one on an
        // already-withdrawn service must not extend its grace deadline.
        // Only live PTRs reactivate, so an address never clears `withdrawn`.
        let withdrawn = !s.is_active;
        let prev_seen = s.last_seen;
        s.last_seen = Instant::now();
        if rec.ttl > 0 && rec.rtype == 12 {
            // Only a live PTR (re)announcement puts the service back on
            // the browse list. Answers to our own SRV re-queries must not
            // resurrect a withdrawn service: the phone is still on the
            // network and answers, but it no longer browses the service.
            // TTL 0 goodbyes pass through without reactivating; mark_goodbye
            // runs first anyway.
            s.is_active = true;
        }
        // Replace the stale copy of the same record (name, type, rdata,
        // source, link): per link, so one source heard on two links keeps
        // a row on each (#264). Owner names fold ASCII case (RFC 6762
        // §16), so a copy in another wire case replaces the row (#402);
        // rdata compares exactly (TXT data is case-sensitive).
        if let Some(pos) = s.answers.iter().position(|r| {
            r.name.eq_ignore_ascii_case(&rec.name)
                && r.rtype == rec.rtype
                && r.rdata == rec.rdata
                && r.source == rec.source
                && r.ifindex == rec.ifindex
        }) {
            s.answers[pos] = rec.clone();
        } else {
            s.answers.push(rec.clone());
        }
        // Fresh answer resets the RFC 6762 §5.2 requery schedule, but only
        // if no row for this key is still inside the 80%-TTL window:
        // sibling rows with other rdata/sources may still need their
        // backoff, and clearing on every unrelated answer re-arms the
        // trigger each loop iteration (reset-driven storm).
        if rec.ttl > 0 {
            let key = (rec.name.trim_end_matches('.').to_string(), rec.rtype);
            let still_expiring = self.services[svc_idx].answers.iter().any(|r| {
                if r.ttl == 0 || r.name.trim_end_matches('.') != key.0.as_str() || r.rtype != key.1
                {
                    return false;
                }
                let elapsed = r.received_at.elapsed().as_secs() as u32;
                elapsed <= r.ttl && in_refresh_window(elapsed, r.ttl)
            });
            if !still_expiring {
                self.scheduler.refresh_answered(&key);
            }
            self.dampen_if_unique(rec);
        }
        // Host-owned records (addresses, and e.g. HINFO for the host
        // name) say the host is alive, not the service. They never
        // reactivate, so a withdrawn service is still withdrawn here:
        // keep its original grace deadline.
        let host_owned = {
            let host = self.services[svc_idx].hostname.trim_end_matches('.');
            !host.is_empty() && rec.name.trim_end_matches('.').eq_ignore_ascii_case(host)
        };
        if withdrawn && (rec.rtype == 1 || rec.rtype == 28 || host_owned) {
            self.services[svc_idx].last_seen = prev_seen;
        }
    }

    /// Flip a service inactive when a goodbye names it. For a PTR goodbye
    /// the withdrawn instance is the rdata (base-type withdrawal, e.g. a
    /// phone stopping its share), so match that too. DNS names are
    /// case-insensitive.
    pub(super) fn mark_goodbye(&mut self, rec: &browse::RawRecord) {
        let mut candidates = vec![rec.name.trim_end_matches('.').to_ascii_lowercase()];
        if rec.rtype == 12 {
            candidates.push(rec.rdata.trim_end_matches('.').to_ascii_lowercase());
        }
        for svc in &mut self.services {
            let full =
                crate::browse::instance_name(&svc.instance, &svc.service_type).to_ascii_lowercase();
            if candidates.iter().any(|n| {
                n == &full || *n == browse::escape_label(&svc.instance).to_ascii_lowercase()
            }) {
                // Another live copy of the withdrawn record (another
                // source, or the same source on another link, #264) keeps
                // the service up: only this copy's row goes `bye`.
                let still_announced = svc.answers.iter().any(|r| {
                    r.rtype == rec.rtype
                        && r.name.eq_ignore_ascii_case(&rec.name)
                        && (rec.rtype != 12 || r.rdata.eq_ignore_ascii_case(&rec.rdata))
                        && !(r.source == rec.source && r.ifindex == rec.ifindex)
                        && record_liveness(r) == RecordLiveness::Live
                });
                if !still_announced {
                    svc.is_active = false;
                }
                return;
            }
        }
    }
}
