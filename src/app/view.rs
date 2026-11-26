// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    pub fn display_items(&self) -> Vec<DisplayItem> {
        struct G {
            label: String,
            indices: Vec<usize>,
        }

        let mut groups: Vec<G> = Vec::new();
        for (i, s) in self.services.iter().enumerate() {
            let key = Self::host_key(&s.hostname);
            match groups.iter_mut().find(|g| g.label == key) {
                Some(g) => g.indices.push(i),
                None => groups.push(G {
                    label: key,
                    indices: vec![i],
                }),
            }
        }

        let mut items = Vec::new();
        // Enumeration group first: global browse state, always present so
        // our own enumeration demand has a home even before any answer.
        items.push(DisplayItem::Host {
            label: ENUM_HOST.to_string(),
        });
        if !self.collapsed_hosts.contains(ENUM_HOST) {
            for (idx, entry) in self.enum_entries.iter().enumerate() {
                let _ = entry;
                items.push(DisplayItem::Enum { index: idx });
            }
        }
        groups.sort_by(|a, b| {
            // Unknown hosts (empty key) sort last.
            match (a.label.is_empty(), b.label.is_empty()) {
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                _ => a.label.cmp(&b.label),
            }
        });
        for g in &groups {
            let mut sorted = g.indices.clone();
            sorted.sort_by(|&a, &b| self.services[a].instance.cmp(&self.services[b].instance));
            items.push(DisplayItem::Host {
                label: g.label.clone(),
            });
            if self.collapsed_hosts.contains(&g.label) {
                continue;
            }
            for idx in sorted {
                items.push(DisplayItem::Instance { index: idx });
            }
        }
        // Findings with no owner, after the host groups; only while any
        // exist, so a clean network shows no extra entry.
        if self.has_unattributed() {
            items.push(DisplayItem::Host {
                label: UNATTRIBUTED_HOST.to_string(),
            });
            if !self.collapsed_hosts.contains(UNATTRIBUTED_HOST) {
                items.push(DisplayItem::Unattributed);
            }
        }
        items
    }

    /// Every A/AAAA record held for each hostname a live service points
    /// at (live SRV targets): filed service rows (deduped across the
    /// services sharing the host), pending addresses and withheld
    /// (NSEC-denied) addresses. Input of `conflicting-answers` (#247).
    pub(super) fn host_address_views(&self) -> Vec<anomalies::HostAddressView<'_>> {
        let mut hosts: Vec<String> = Vec::new();
        for svc in &self.services {
            for host in Self::service_hosts(svc) {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        hosts
            .into_iter()
            .map(|host| {
                let mut seen = HashSet::new();
                let records = self
                    .services
                    .iter()
                    .flat_map(|s| s.answers.iter())
                    .filter(|r| matches!(r.rtype, 1 | 28) && anomalies::host_id(&r.name) == host)
                    .chain(self.pending_addrs.get(&host).into_iter().flatten())
                    .chain(self.address_denials.withheld(&host))
                    // Live copies only, before the dedup and from every
                    // source: a stale copy (an earlier service's, or a
                    // pending one) must not shadow a live one.
                    .filter(|r| record_liveness(r) == RecordLiveness::Live)
                    .filter(|r| {
                        seen.insert((
                            r.rtype,
                            r.rdata.as_str(),
                            r.source,
                            r.iface.as_str(),
                            r.ifindex,
                        ))
                    })
                    .collect();
                anomalies::HostAddressView { host, records }
            })
            .collect()
    }

    /// Device names for source addresses (#246), from live A/AAAA
    /// records: service answers, enumeration rows, pending services,
    /// pending addresses and withheld (NSEC-denied) host addresses. Rebuilt on demand; never cached.
    pub fn address_book(&self) -> AddressBook {
        let host_keys = self
            .services
            .iter()
            .map(|s| Self::host_key(&s.hostname))
            .filter(|k| !k.is_empty())
            .collect();
        let mut book = AddressBook::new(host_keys);
        let records = self
            .services
            .iter()
            .flat_map(|s| s.answers.iter())
            .chain(self.enum_entries.iter().flat_map(|e| e.answers.iter()))
            .chain(self.pending_instances.iter().flat_map(|p| p.answers.iter()))
            .chain(self.pending_addrs.values().flatten())
            // Denied on every service (#245) but still the host's live
            // addresses: the host header shows them, so naming does too.
            .chain(self.address_denials.all_withheld());
        for rec in records {
            book.add(rec);
        }
        book
    }

    /// Whether any live sighting has no owner (it would be filed under
    /// `anomalies::UNATTRIBUTED_SERVICE`). Cheap: no analyzer run.
    pub(super) fn has_unattributed(&self) -> bool {
        let now = Instant::now();
        self.sightings
            .iter()
            .any(|s| s.is_live(now) && self.sighting_owners(s).is_empty())
    }

    /// Normalized group key for host grouping: lowercased hostname without
    /// trailing dot, `""` when the service has no hostname yet.
    /// Same normalization as `anomalies::host_id`, so a host group's
    /// key is also the owner id of its host-owned findings.
    pub(super) fn host_key(hostname: &str) -> String {
        anomalies::host_id(hostname)
    }

    /// Display name for a host group key: first-seen hostname without its
    /// trailing dot or redundant `.local` suffix, or `(unknown host)` when
    /// no hostname is known yet. Grouping keys keep the full name; this
    /// is display-only.
    pub fn host_display_name(&self, key: &str) -> String {
        if key.is_empty() {
            return "(unknown host)".to_string();
        }
        if key == ENUM_HOST {
            return ENUM_GROUP_NAME.to_string();
        }
        if key == UNATTRIBUTED_HOST {
            return UNATTRIBUTED_GROUP_NAME.to_string();
        }
        for s in &self.services {
            if Self::host_key(&s.hostname) == key {
                let trimmed = s.hostname.trim_end_matches('.');
                if !trimmed.is_empty() {
                    return Self::short_hostname(trimmed);
                }
            }
        }
        Self::short_hostname(key)
    }

    /// Short display form of a hostname: the redundant `.local` suffix
    /// removed (`printer.local.` → `printer`). Case-insensitive; names
    /// that merely contain `local` elsewhere are untouched.
    pub(super) fn short_hostname(name: &str) -> String {
        browse::unescape_name(
            browse::strip_local_suffix(name).unwrap_or_else(|| name.trim_end_matches('.')),
        )
    }

    /// Live addresses (A/AAAA rdata) aggregated across all services on the
    /// host, deduped with IPv4 first. Expired rows are omitted.
    pub fn host_addresses(&self, key: &str) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        // Every target whose filed rows count here; withheld rows use the
        // same set.
        let mut all_targets: HashSet<String> = HashSet::from([key.to_string()]);
        for s in &self.services {
            if Self::host_key(&s.hostname) != key {
                continue;
            }
            // Collect the live SRV targets for this service so addresses
            // published under an alternate (non-selected) target are still
            // surfaced on the selected host.
            let mut targets = vec![key.to_string()];
            for r in &s.answers {
                if r.rtype != 33 {
                    continue;
                }
                if r.ttl <= r.received_at.elapsed().as_secs() as u32 {
                    continue;
                }
                let t = r
                    .rdata
                    .splitn(4, ' ')
                    .nth(3)
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('.')
                    .to_ascii_lowercase();
                if !t.is_empty() && !targets.contains(&t) {
                    targets.push(t);
                }
            }
            all_targets.extend(targets.iter().cloned());
            for rec in &s.answers {
                if rec.rtype != 1 && rec.rtype != 28 {
                    continue;
                }
                if rec.ttl <= rec.received_at.elapsed().as_secs() as u32 {
                    continue;
                }
                let owner = rec.name.trim_end_matches('.').to_ascii_lowercase();
                if !targets.contains(&owner) {
                    continue;
                }
                let ip = rec.rdata.trim().to_string();
                if ip.is_empty() || !seen.insert(ip.clone()) {
                    continue;
                }
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    if addr.is_ipv4() {
                        v4.push(ip);
                    } else {
                        v6.push(ip);
                    }
                } else if rec.rtype == 1 {
                    v4.push(ip);
                } else {
                    v6.push(ip);
                }
            }
        }
        // Addresses withheld from every service of this host by an NSEC
        // denial (#245) are still the host's own addresses.
        let withheld = all_targets
            .iter()
            .flat_map(|target| self.address_denials.withheld(target));
        for rec in withheld {
            if rec.ttl <= rec.received_at.elapsed().as_secs() as u32 {
                continue;
            }
            let ip = rec.rdata.trim().to_string();
            if ip.is_empty() || !seen.insert(ip.clone()) {
                continue;
            }
            if rec.rtype == 1 {
                v4.push(ip);
            } else {
                v6.push(ip);
            }
        }
        v4.sort();
        v6.sort();
        v4.extend(v6);
        v4
    }

    pub fn host_service_count(&self, key: &str) -> usize {
        if key == ENUM_HOST {
            return self.enum_entries.len();
        }
        if key == UNATTRIBUTED_HOST {
            return 1;
        }
        self.services
            .iter()
            .filter(|s| Self::host_key(&s.hostname) == key)
            .count()
    }

    /// Confirmation popup text while fresh (3s); `None` once expired.
    pub fn status_popup(&self) -> Option<String> {
        let (text, since) = self.status_msg.as_ref()?;
        if since.elapsed() <= Duration::from_secs(3) {
            Some(text.clone())
        } else {
            None
        }
    }

    pub fn is_host_collapsed(&self, label: &str) -> bool {
        self.collapsed_hosts.contains(label)
    }

    /// Number of distinct non-empty `; `-separated pairs in TXT rdata.
    pub fn txt_pair_count(rdata: &str) -> usize {
        let mut seen = HashSet::new();
        rdata
            .split("; ")
            .filter(|pair| !pair.is_empty() && seen.insert(*pair))
            .count()
    }

    /// Whether a record renders with collapsible TXT child rows (multi-pair TXT).
    pub fn is_expandable_txt(rec: &browse::RawRecord) -> bool {
        rec.rtype == 16 && Self::txt_pair_count(&rec.rdata) > 1
    }

    pub(super) fn txt_key(rec: &browse::RawRecord) -> TxtKey {
        (rec.name.clone(), rec.rdata.clone(), rec.source, rec.ifindex)
    }

    /// Collapsed by default: only answers explicitly expanded via `Enter`
    /// show their child rows.
    pub fn is_txt_expanded(&self, rec: &browse::RawRecord) -> bool {
        self.expanded_txt.contains(&Self::txt_key(rec))
    }

    pub fn is_local_record(&self, rec: &browse::RawRecord) -> bool {
        self.is_local_source(&rec.source)
    }

    pub fn is_local_source(&self, source: &std::net::SocketAddr) -> bool {
        self.local_ips.contains(&source.ip())
    }

    pub fn selected_service(&self) -> Option<&ServiceEntry> {
        let items = self.display_items();
        match items.get(self.view_state.selected_display)? {
            DisplayItem::Instance { index } => self.services.get(*index),
            _ => None,
        }
    }

    pub fn selected_enum(&self) -> Option<&EnumEntry> {
        let items = self.display_items();
        match items.get(self.view_state.selected_display)? {
            DisplayItem::Enum { index } => self.enum_entries.get(*index),
            _ => None,
        }
    }

    pub fn latest_event_for_selected(&self) -> Option<&browse::Event> {
        // Newest record first, then the target's last-seen packet: the
        // shared buffer ages with total traffic, so a quiet target's
        // packets may all be gone while its answers live on.
        let target = self.display_detail()?;
        for rec in target.all_answers().iter().rev() {
            if let Some(ev) = self
                .raw_events
                .iter()
                .rev()
                .find(|ev| ev.source == rec.source)
            {
                return Some(ev);
            }
        }
        target.last_event()
    }

    /// Service shown in the right panes: the selected one, or the last
    /// selected one while the cursor sits on a service-type header.
    /// Kept for tests; the panes render through `display_detail`.
    #[cfg(test)]
    pub fn display_service(&self) -> Option<&ServiceEntry> {
        if let Some(svc) = self.selected_service() {
            return Some(svc);
        }
        let key = self.sticky_key.as_ref()?;
        self.services
            .iter()
            .find(|s| s.service_type == key.0 && s.instance == key.1)
    }

    /// Right-pane target: the selected service or enumeration row, or the
    /// last selected one while the cursor sits on a header.
    pub fn display_detail(&self) -> Option<DetailTarget<'_>> {
        if let Some(svc) = self.selected_service() {
            return Some(DetailTarget::Service(svc));
        }
        if let Some(entry) = self.selected_enum() {
            return Some(DetailTarget::Enum(entry));
        }
        if self.unattributed_selected() {
            return Some(DetailTarget::Unattributed);
        }
        if let Some(key) = self.sticky_key.as_ref() {
            if let Some(svc) = self
                .services
                .iter()
                .find(|s| s.service_type == key.0 && s.instance == key.1)
            {
                return Some(DetailTarget::Service(svc));
            }
        }
        if let Some(key) = self.sticky_enum_key.as_ref() {
            if let Some(entry) = self.enum_entries.iter().find(|e| &e.name == key) {
                return Some(DetailTarget::Enum(entry));
            }
        }
        // Folding the group parks on its header; keep showing it while
        // it exists.
        if self.sticky_unattributed && self.has_unattributed() {
            return Some(DetailTarget::Unattributed);
        }
        None
    }

    /// Whether the Hosts cursor sits on the `(unattributed)` row.
    pub(super) fn unattributed_selected(&self) -> bool {
        matches!(
            self.display_items().get(self.view_state.selected_display),
            Some(DisplayItem::Unattributed)
        )
    }

    /// Entry under the Tab cursor in the Records table: a raw record row or
    /// a question row (table order is raw answers first, then questions
    /// by type/newest-first, matching the rendered table).
    pub fn selected_detail_entry(&self) -> Option<DetailEntry<'_>> {
        let target = self.display_detail()?;
        match &target {
            DetailTarget::Service(svc) => {
                let key = (svc.service_type.clone(), svc.instance.clone());
                if self.detail_svc_key.as_ref() != Some(&key) {
                    return None;
                }
            }
            DetailTarget::Enum(entry) => {
                if self.detail_enum_key.as_ref() != Some(&entry.name) {
                    return None;
                }
            }
            // No rows of its own: nothing for the cursor or hex pane.
            DetailTarget::Unattributed => return None,
        }
        let raws = target.ordered_answers();
        if self.view_state.detail_selected < raws.len() {
            return Some(DetailEntry::Record(raws[self.view_state.detail_selected]));
        }
        target
            .ordered_questions()
            .into_iter()
            .nth(self.view_state.detail_selected - raws.len())
            .map(|q| DetailEntry::Question {
                name: &q.0,
                rtype_str: &q.1,
                raw: &q.4,
                source: &q.2,
            })
    }

    /// The Answers table for `target`, line by line (#248): derived info
    /// rows, then the `service` block (findings of this owner with no row
    /// of their own), one `host <name>` block per live SRV-target host
    /// with host-owned findings, then every record row followed by its
    /// findings and (expanded) TXT pairs. Gone rows carry no findings.
    /// The unattributed view groups its findings by name instead.
    pub fn answers_layout(
        &self,
        target: &DetailTarget<'_>,
        found: &[anomalies::Anomaly],
    ) -> Vec<AnswerLine> {
        let mut lines = Vec::new();
        let id = Self::detail_service_id(target);
        let own: Vec<&anomalies::Anomaly> = found.iter().filter(|a| a.service == id).collect();
        match target {
            DetailTarget::Service(svc) => {
                lines.push(AnswerLine::Info {
                    label: "srvc",
                    text: svc.service_type.clone(),
                });
                let mut seen = HashSet::new();
                for sub in svc.subtypes.iter().filter(|sub| seen.insert(*sub)) {
                    lines.push(AnswerLine::Info {
                        label: "subt",
                        text: anomalies::display_subtype(sub),
                    });
                }
            }
            DetailTarget::Enum(entry) => lines.push(AnswerLine::Info {
                label: "enum",
                text: entry.name.clone(),
            }),
            DetailTarget::Unattributed => {
                let mut names: Vec<String> = Vec::new();
                for a in &own {
                    let name = a.record_name.clone().unwrap_or_default();
                    if !names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                        names.push(name);
                    }
                }
                names.sort_by_key(|n| n.to_lowercase());
                for name in names {
                    lines.push(AnswerLine::Block(name.clone()));
                    for a in own.iter().filter(|a| {
                        a.record_name
                            .as_deref()
                            .unwrap_or_default()
                            .eq_ignore_ascii_case(&name)
                    }) {
                        lines.push(AnswerLine::Finding {
                            anomaly: Box::new((*a).clone()),
                            record: None,
                        });
                    }
                }
                return lines;
            }
        }

        let answers = target.ordered_answers();
        let questions = target.ordered_questions();
        let mut placed = vec![false; own.len()];
        let mut row_findings: Vec<Vec<anomalies::Anomaly>> = vec![Vec::new(); answers.len()];
        for (i, rec) in answers.iter().enumerate() {
            if record_liveness(rec) != RecordLiveness::Live {
                continue;
            }
            for (j, a) in own.iter().enumerate() {
                if !a.kind.is_question() && finding_matches_record(a, rec) {
                    row_findings[i].push((*a).clone());
                    placed[j] = true;
                }
            }
        }
        for (name, rtype_str, source, _, _) in &questions {
            for (j, a) in own.iter().enumerate() {
                if finding_matches_question(a, name, rtype_str, source) {
                    placed[j] = true;
                }
            }
        }
        let rowless: Vec<&anomalies::Anomaly> = own
            .iter()
            .zip(&placed)
            .filter(|(_, placed)| !**placed)
            .map(|(a, _)| *a)
            .collect();
        if !rowless.is_empty() {
            let label = match target {
                DetailTarget::Enum(_) => "enumeration",
                _ => "service",
            };
            lines.push(AnswerLine::Block(label.to_string()));
            lines.extend(rowless.into_iter().map(|a| AnswerLine::Finding {
                anomaly: Box::new(a.clone()),
                record: None,
            }));
        }
        if let DetailTarget::Service(svc) = target {
            for host in Self::service_hosts(svc) {
                let host_findings: Vec<&anomalies::Anomaly> =
                    found.iter().filter(|a| a.service == host).collect();
                if host_findings.is_empty() {
                    continue;
                }
                lines.push(AnswerLine::Block(format!(
                    "host {}",
                    Self::short_hostname(&host)
                )));
                lines.extend(host_findings.into_iter().map(|a| AnswerLine::Finding {
                    anomaly: Box::new(a.clone()),
                    record: None,
                }));
            }
        }
        for (i, rec) in answers.iter().enumerate() {
            lines.push(AnswerLine::Record(i));
            lines.extend(
                row_findings[i]
                    .drain(..)
                    .map(|anomaly| AnswerLine::Finding {
                        anomaly: Box::new(anomaly),
                        record: Some(i),
                    }),
            );
            // Multi-pair TXT children only while expanded (a lone pair
            // is already the parent's rdata).
            if !(Self::is_expandable_txt(rec) && self.is_txt_expanded(rec)) {
                continue;
            }
            let mut seen_pair = HashSet::new();
            let mut pairs: Vec<&str> = rec
                .rdata
                .split("; ")
                .filter(|pair| !pair.is_empty() && seen_pair.insert(*pair))
                .collect();
            pairs.sort_by(|a, b| {
                let ka = a.split('=').next().unwrap_or(a);
                let kb = b.split('=').next().unwrap_or(b);
                ka.to_lowercase()
                    .cmp(&kb.to_lowercase())
                    .then_with(|| ka.cmp(kb))
                    .then_with(|| a.cmp(b))
            });
            if pairs.len() > 1 {
                let n = pairs.len();
                for (k, pair) in pairs.into_iter().enumerate() {
                    lines.push(AnswerLine::TxtPair {
                        record: i,
                        pair: pair.to_string(),
                        last: k + 1 == n,
                    });
                }
            }
        }
        lines
    }

    /// Service id owning a detail target, matching `Anomaly.service`.
    pub(super) fn detail_service_id(target: &DetailTarget<'_>) -> String {
        match target {
            DetailTarget::Service(s) => anomalies::service_id(&s.instance, &s.service_type),
            DetailTarget::Enum(_) => anomalies::ENUMERATION_SERVICE.to_string(),
            DetailTarget::Unattributed => anomalies::UNATTRIBUTED_SERVICE.to_string(),
        }
    }

    /// Field ranges for the selected record or uniquely matched query question.
    pub fn selected_detail_fields(&self) -> Option<Vec<browse::RecordField>> {
        match self.selected_detail_entry()? {
            DetailEntry::Record(record) => Some(browse::record_fields(&record.wire, record.rtype)),
            DetailEntry::Question {
                name,
                rtype_str,
                raw,
                ..
            } if !raw.is_empty() => browse::question_fields(raw, name, rtype_str),
            DetailEntry::Question { .. } => None,
        }
    }

    /// Hex dump payload: selected record bytes or the stored query packet.
    pub fn selected_detail_bytes(&self) -> Option<(Vec<u8>, String)> {
        match self.selected_detail_entry()? {
            DetailEntry::Record(rec) => {
                if rec.wire.is_empty() {
                    return None;
                }
                Some((
                    rec.wire.clone(),
                    format!(" {} {} ", rec.rtype_str, browse::unescape_name(&rec.name)),
                ))
            }
            DetailEntry::Question {
                name,
                rtype_str,
                raw,
                source,
            } => {
                let title = format!(" QRY {rtype_str} {} ", browse::unescape_name(name));
                if *source == SELF_SOURCE {
                    return Some((raw.to_vec(), format!("{title}(inferred) ")));
                }
                if raw.is_empty() {
                    let fallback = self
                        .latest_event_for_selected()
                        .map(|ev| ev.raw_bytes.clone())
                        .unwrap_or_default();
                    return Some((fallback, format!("{title}(raw packet) ")));
                }
                Some((raw.to_vec(), title))
            }
        }
    }

    /// Services currently browsed, indexed by `DisplayItem::Service`.
    pub fn services(&self) -> &[ServiceEntry] {
        &self.services
    }

    /// Enumeration rows, indexed by `DisplayItem::Enum`.
    pub fn enum_entries(&self) -> &[EnumEntry] {
        &self.enum_entries
    }

    /// mDNS packets received since startup.
    pub fn packet_count(&self) -> u64 {
        self.packet_count
    }

    /// When browsing started, for the uptime in the header.
    pub fn start_time(&self) -> Instant {
        self.start_time
    }

    /// Listen-only mode (`--passive`): never transmit queries.
    pub fn is_passive(&self) -> bool {
        self.passive
    }
}
