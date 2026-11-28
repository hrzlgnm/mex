// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// Nerd Font level icon for an anomaly severity, shown in place of the
    /// severity word in diagnostics keys. FontAwesome subset (single cell in
    /// every Nerd Font): U+F057 times-circle (error), U+F071 warning
    /// (warning), U+F05A info-circle (info).
    pub(crate) fn anomaly_level_icon(severity: anomalies::Severity) -> char {
        match severity {
            anomalies::Severity::Error => '\u{f057}',
            anomalies::Severity::Warning => '\u{f071}',
            anomalies::Severity::Info => '\u{f05a}',
        }
    }

    /// Pure anomaly snapshot over live browser state. Read-only: never
    /// touches query scheduling, ingest, or expiry. Cheap enough to rebuild
    /// per overlay frame (tens of services, hundreds of records).
    /// Flatten one question list into analyzer views, resolving the
    /// displayed type label back to its numeric type. Labels the parser
    /// never emits stay quiet.
    pub(super) fn push_question_views<'a>(
        out: &mut Vec<anomalies::QuestionView<'a>>,
        service: String,
        rows: &'a [QuestionRow],
    ) {
        for (name, rtype_str, source, _, _) in rows {
            if let Some(rtype) = browse::rtype_from_str(rtype_str) {
                out.push(anomalies::QuestionView {
                    service: service.clone(),
                    name,
                    rtype,
                    rtype_str,
                    source: *source,
                    // Questions rows carry no ingress link.
                    source_label: source.to_string(),
                });
            }
        }
    }

    pub fn anomalies(&self) -> Vec<anomalies::Anomaly> {
        let mut services: Vec<anomalies::ServiceView<'_>> = self
            .services
            .iter()
            .map(|s| anomalies::ServiceView {
                instance: &s.instance,
                service_type: &s.service_type,
                answers: &s.answers,
                subtypes: &s.subtypes,
                denied_address_types: self
                    .address_denials
                    .denied_types(&service_key(&s.instance, &s.service_type)),
            })
            .collect();
        // Pending instances hold PTR/TXT rows that arrived before their
        // SRV: they deserve the same checks. Dedup in the analyzer keeps
        // rows already represented on a confirmed service to one finding;
        // the identity format matches so shared findings collapse.
        for p in &self.pending_instances {
            services.push(anomalies::ServiceView {
                instance: &p.instance,
                service_type: &p.service_type,
                answers: &p.answers,
                subtypes: &p.subtypes,
                denied_address_types: self
                    .address_denials
                    .denied_types(&service_key(&p.instance, &p.service_type)),
            });
        }
        let enum_answers: Vec<&browse::RawRecord> = self
            .enum_entries
            .iter()
            .flat_map(|e| e.answers.iter())
            .collect();
        let pending_hosts: HashSet<String> = self.pending_addrs.keys().cloned().collect();
        let address_queries: Vec<_> = self
            .services
            .iter()
            .flat_map(|service| {
                let service_id = anomalies::service_id(&service.instance, &service.service_type);
                let mut targets = HashSet::new();
                for rec in service.answers.iter().filter(|rec| {
                    rec.rtype == 33
                        && rec.ttl > 0
                        && rec.received_at.elapsed().as_secs() <= u64::from(rec.ttl)
                }) {
                    if let Some(host) = rec.rdata.split_whitespace().last() {
                        targets.insert(host.trim_end_matches('.').to_ascii_lowercase());
                    }
                }
                targets.into_iter().flat_map(move |hostname| {
                    let service_id = service_id.clone();
                    [1, 28].into_iter().filter_map(move |rtype| {
                        self.scheduler
                            .history(&Scheduler::provenance_key(&hostname, rtype))
                            .and_then(|state| state.transmitted.map(|at| (state, at)))
                            .map(|(state, transmitted_at)| anomalies::AddressQueryView {
                                service: service_id.clone(),
                                hostname: hostname.clone(),
                                rtype,
                                transmitted_at,
                                interfaces: state.transmitted_interfaces.clone(),
                            })
                    })
                })
            })
            .collect();
        // Observed questions flattened with their owning service id, so the
        // analyzer can attribute demand-side unicast-type questions the
        // same way it does answer sightings. Unrecognised type labels stay quiet.
        let mut questions: Vec<anomalies::QuestionView<'_>> = Vec::new();
        for s in &self.services {
            Self::push_question_views(
                &mut questions,
                anomalies::service_id(&s.instance, &s.service_type),
                &s.questions,
            );
        }
        for p in &self.pending_instances {
            Self::push_question_views(
                &mut questions,
                anomalies::service_id(&p.instance, &p.service_type),
                &p.questions,
            );
        }
        for e in &self.enum_entries {
            Self::push_question_views(
                &mut questions,
                anomalies::ENUMERATION_SERVICE.to_string(),
                &e.questions,
            );
        }
        // Out-of-scope sightings: one analyzer entry per owner, resolved
        // now so later-appearing services claim earlier sightings.
        let now = Instant::now();
        let mut sightings = Vec::new();
        for s in self.sightings.iter().filter(|s| s.is_live(now)) {
            let mut owners = self.sighting_owners(s);
            if owners.is_empty() {
                owners.push(anomalies::UNATTRIBUTED_SERVICE.to_string());
            }
            for service in owners {
                match s.kind {
                    SightingKind::Question => questions.push(anomalies::QuestionView {
                        service,
                        name: &s.rec.name,
                        rtype: s.rec.rtype,
                        rtype_str: &s.rec.rtype_str,
                        source: s.rec.source,
                        source_label: s.rec.source_label(),
                    }),
                    SightingKind::Response | SightingKind::KnownAnswer => {
                        sightings.push((service, &s.rec))
                    }
                }
            }
        }
        let host_addresses = self.host_address_views();
        let book = self.address_book();
        // Responders behind the address records, and every querier in the
        // retained packets (a rate finding names what its repeats answered).
        let queriers = self
            .raw_events
            .iter()
            .filter(|ev| !ev.questions.is_empty() && !ev.is_ignored())
            .map(|ev| ev.source.ip());
        let device_names = host_addresses
            .iter()
            .flat_map(|v| v.records.iter())
            .map(|r| r.source.ip())
            .chain(queriers)
            .collect::<HashSet<_>>()
            .into_iter()
            .filter_map(|ip| {
                book.resolve(ip).map(|d| {
                    let label = anomalies::DeviceLabel {
                        id: d.host_id(),
                        name: d.display(),
                    };
                    (ip, label)
                })
            })
            .collect();
        let snap = anomalies::Snapshot {
            services,
            enum_answers,
            pending_hosts,
            questions,
            sightings,
            host_addresses,
            device_names,
        };
        let found = anomalies::analyze_observations(
            &snap,
            &self.raw_events,
            &self.own_sends,
            &address_queries,
        );
        self.unattributed_findings.set(
            found
                .iter()
                .any(|a| a.service == anomalies::UNATTRIBUTED_SERVICE),
        );
        found
    }

    /// Per-service anomaly counts keyed by service id (`anomalies::service_id`).
    /// Used for host-list markers and the Answers table
    /// without recomputing per row. Informational notes never count.
    #[cfg(test)]
    pub fn anomaly_counts(&self) -> HashMap<String, usize> {
        Self::anomaly_counts_in(&self.anomalies())
            .into_iter()
            .map(|(owner, (n, _))| (owner, n))
            .collect()
    }

    /// `anomaly_counts` over a precomputed finding set, so a frame runs
    /// the analyzer once instead of once per pane.
    pub fn anomaly_counts_in(
        found: &[anomalies::Anomaly],
    ) -> HashMap<String, (usize, anomalies::Severity)> {
        // Every finding counts, info included (#248): each owner's badge
        // names how many findings sit next to it and the worst level.
        let mut counts: HashMap<String, (usize, anomalies::Severity)> = HashMap::new();
        for a in found {
            let entry = counts.entry(a.service.clone()).or_insert((0, a.severity));
            entry.0 += 1;
            if a.severity.rank() > entry.1.rank() {
                entry.1 = a.severity;
            }
        }
        counts
    }

    /// Findings shown under each Questions row of `target`, aligned with
    /// `ordered_questions` (#248).
    pub fn question_findings(
        &self,
        target: &DetailTarget<'_>,
        found: &[anomalies::Anomaly],
    ) -> Vec<Vec<anomalies::Anomaly>> {
        let id = Self::detail_service_id(target);
        target
            .ordered_questions()
            .iter()
            .map(|(name, rtype_str, source, _, _)| {
                found
                    .iter()
                    .filter(|a| a.service == id)
                    .filter(|a| finding_matches_question(a, name, rtype_str, source))
                    .cloned()
                    .collect()
            })
            .collect()
    }
}
