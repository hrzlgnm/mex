// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// Hostnames a service lives on, lowercased without the root dot:
    /// every live SRV target. The selected hostname alone is no evidence:
    /// it outlives an expired SRV while the PTR is still live.
    pub(crate) fn service_hosts(svc: &ServiceEntry) -> Vec<String> {
        let mut hosts = Vec::new();
        for r in &svc.answers {
            if r.rtype != 33 || r.ttl <= r.received_at.elapsed().as_secs() as u32 {
                continue;
            }
            if let Some(target) = srv_target(&r.rdata) {
                let target = anomalies::host_id(target);
                if !hosts.contains(&target) {
                    hosts.push(target);
                }
            }
        }
        hosts
    }

    /// Finding owners for an out-of-scope record or question:
    /// * enumeration names belong to the enumeration row;
    /// * an instance name belongs to that live or pending service
    ///   (questions also match the service type, like `route_question`);
    /// * a hostname any live service lives on belongs to the host
    ///   itself (`anomalies::host_id`), once, not to each service on it.
    ///
    /// Empty when nothing matches.
    pub(super) fn sighting_owners(&self, sighting: &Sighting) -> Vec<String> {
        let name = sighting.rec.name.trim_end_matches('.').to_ascii_lowercase();
        let question = sighting.kind == SightingKind::Question;
        if is_enum_name(&name) {
            return vec![anomalies::ENUMERATION_SERVICE.to_string()];
        }
        let mut owners: Vec<String> = Vec::new();
        let mut add = |id: String| {
            if !owners.contains(&id) {
                owners.push(id);
            }
        };
        for svc in &self.services {
            let full =
                crate::browse::instance_name(&svc.instance, &svc.service_type).to_ascii_lowercase();
            if full == name || (question && svc.service_type.to_ascii_lowercase() == name) {
                add(anomalies::service_id(&svc.instance, &svc.service_type));
            }
            if Self::service_hosts(svc).contains(&name) {
                add(anomalies::host_id(&name));
            }
        }
        for p in &self.pending_instances {
            let full =
                crate::browse::instance_name(&p.instance, &p.service_type).to_ascii_lowercase();
            if full == name || (question && p.service_type.to_ascii_lowercase() == name) {
                add(anomalies::service_id(&p.instance, &p.service_type));
            }
        }
        owners
    }

    /// File an out-of-scope record or question as a sighting. A TTL-0
    /// response record withdraws its sighting instead (it never reaches
    /// the goodbye paths, so no real answer row is marked gone); a
    /// known answer is never a goodbye. Re-filing moves the sighting to
    /// the back, so the cap evicts the one seen least recently.
    pub(super) fn ingest_sighting(&mut self, kind: SightingKind, rec: browse::RawRecord) {
        if kind == SightingKind::Response && rec.ttl == 0 {
            let before = self.sightings.len();
            self.sightings.retain(|s| !s.same_record(kind, &rec));
            if self.sightings.len() != before {
                self.touch();
            }
            return;
        }
        self.sightings.retain(|s| !s.same_identity(kind, &rec));
        self.sightings.push(Sighting { kind, rec });
        if self.sightings.len() > SIGHTINGS_CAP {
            self.sightings.remove(0);
            self.diagnostics.sightings_dropped += 1;
        }
        self.touch();
    }
}
