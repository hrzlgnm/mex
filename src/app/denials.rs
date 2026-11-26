// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// How a responder said an address type is absent for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum DenialForm {
    /// RFC 6762 §6.1: a hostname-owned NSEC, arriving in the same packet
    /// as the service's SRV for that host, whose bitmap lists the types
    /// that exist; absent address types are denied.
    Rfc,
    /// Older python-zeroconf: an instance-owned NSEC whose bitmap lists
    /// only the *missing* address types (inverted bitmap).
    Legacy,
}

impl DenialForm {
    fn as_str(self) -> &'static str {
        match self {
            DenialForm::Rfc => "rfc",
            DenialForm::Legacy => "legacy",
        }
    }
}

/// A service's own responder said it has no address of `rtype` (A or
/// AAAA): rows of that type stay off this service while it is live.
#[derive(Debug, Clone)]
pub(super) struct AddressDenial {
    /// Lowercased service name in presentation form (`service_key`).
    service: String,
    rtype: u16,
    /// The hostname it applies to (RFC form); `None` for every host of
    /// the service (legacy, instance-owned form).
    host: Option<String>,
    form: DenialForm,
    source: std::net::SocketAddr,
    ttl: u32,
    received_at: Instant,
}

impl AddressDenial {
    fn is_live(&self) -> bool {
        self.ttl > 0 && self.received_at.elapsed().as_secs() <= u64::from(self.ttl)
    }

    /// Whether this denial is about an address of `rtype` owned by `host`.
    pub(super) fn applies_to(&self, rtype: u16, host: &str) -> bool {
        self.rtype == rtype && self.host.as_deref().is_none_or(|h| h == host)
    }

    fn covers(&self, service: &str, rtype: u16, host: &str) -> bool {
        self.service == service && self.applies_to(rtype, host) && self.is_live()
    }

    /// Lowercased service name (`service_key`) this denial keeps rows off.
    pub(super) fn service(&self) -> &str {
        &self.service
    }
}

/// NSEC address denials (#245) and the addresses they withhold.
///
/// Owns which services a responder said have no A or AAAA, and the
/// address rows kept off every service of their host because of that.
/// `App` decides what to do with the rows of a newly denied service;
/// this type only tracks the denials and the withheld copies.
#[derive(Debug, Default)]
pub(super) struct AddressDenials {
    denials: Vec<AddressDenial>,
    /// Address records withheld from every service of their host by a
    /// denial, by lowercased host: the Hosts header still lists them.
    withheld: HashMap<String, Vec<browse::RawRecord>>,
}

/// What [`AddressDenials::ingest`] changed.
#[derive(Debug, Default)]
pub(super) struct DenialUpdate {
    /// Any denial was added, refreshed or lifted.
    pub(super) changed: bool,
    /// Live denials recorded by this packet, in order: their service's
    /// matching address rows must come off it.
    pub(super) applied: Vec<AddressDenial>,
}

impl AddressDenials {
    /// Apply NSEC address denials in a response (#245). Each NSEC states
    /// the full set of types at its owner, so it both adds and lifts:
    /// * RFC form: a hostname-owned NSEC in the same packet as a
    ///   service's SRV for that host denies the address types absent
    ///   from its bitmap and lifts those present, for that service and
    ///   host only;
    /// * legacy form: an instance-owned NSEC whose bitmap holds only A
    ///   and/or AAAA denies the listed types and lifts the others; any
    ///   other instance NSEC (the compliant SRV/TXT form) lifts them all;
    /// * a TTL-0 NSEC withdraws every denial its owner made, with or
    ///   without an SRV in the packet.
    ///
    /// `instances` are the live service keys (`service_key`) known
    /// before this packet.
    pub(super) fn ingest(
        &mut self,
        ev: &browse::Event,
        mut instances: HashSet<String>,
    ) -> DenialUpdate {
        let mut update = DenialUpdate::default();
        let srvs: Vec<(String, String)> = ev
            .answers
            .iter()
            .filter(|r| r.rtype == 33 && r.ttl > 0)
            .filter_map(|r| {
                let target = srv_target(&r.rdata)?.to_ascii_lowercase();
                Some((r.name.trim_end_matches('.').to_ascii_lowercase(), target))
            })
            .collect();
        // This packet's SRVs name instances too (they are filed next).
        instances.extend(srvs.iter().map(|(service, _)| service.clone()));
        // ...and so do its PTR targets and TXT owners (an instance NSEC
        // can arrive with the PTR before any SRV).
        for r in ev.answers.iter().filter(|r| r.ttl > 0) {
            match r.rtype {
                12 if !is_enum_name(r.name.trim_end_matches('.')) => {
                    instances.insert(r.rdata.trim_end_matches('.').to_ascii_lowercase());
                }
                16 => {
                    instances.insert(r.name.trim_end_matches('.').to_ascii_lowercase());
                }
                _ => {}
            }
        }
        for nsec in ev.answers.iter().filter(|r| r.rtype == 47) {
            let owner = nsec.name.trim_end_matches('.').to_ascii_lowercase();
            let (address, other) = browse::nsec_address_types(&nsec.rdata);
            let denial =
                |service: &str, rtype: u16, host: Option<&str>, form: DenialForm| AddressDenial {
                    service: service.to_string(),
                    rtype,
                    host: host.map(str::to_string),
                    form,
                    source: nsec.source,
                    ttl: nsec.ttl,
                    received_at: nsec.received_at,
                };
            if nsec.ttl == 0 {
                // Goodbye: lift whatever this owner denied, anywhere.
                let before = self.denials.len();
                self.denials.retain(|d| {
                    d.host.as_deref() != Some(owner.as_str())
                        && !(d.host.is_none() && d.service == owner)
                });
                update.changed |= self.denials.len() != before;
                continue;
            }
            for (service, _) in srvs.iter().filter(|(_, target)| *target == owner) {
                for rtype in [1, 28] {
                    let d = denial(service, rtype, Some(&owner), DenialForm::Rfc);
                    if address.contains(&rtype) {
                        update.changed |= self.lift(&d);
                    } else {
                        self.apply(d, &mut update);
                    }
                }
            }
            if instances.contains(&owner) {
                let inverted = !address.is_empty() && !other;
                for rtype in [1, 28] {
                    let d = denial(&owner, rtype, None, DenialForm::Legacy);
                    if inverted && address.contains(&rtype) {
                        self.apply(d, &mut update);
                    } else {
                        update.changed |= self.lift(&d);
                    }
                }
            }
        }
        update
    }

    /// Drop any denial with the same identity (service, type, host).
    fn lift(&mut self, denial: &AddressDenial) -> bool {
        let before = self.denials.len();
        self.denials.retain(|d| {
            !(d.service == denial.service && d.rtype == denial.rtype && d.host == denial.host)
        });
        self.denials.len() != before
    }

    /// Record (or refresh) one denial. A live one is reported in
    /// `update.applied` so its service's rows can be taken off.
    fn apply(&mut self, denial: AddressDenial, update: &mut DenialUpdate) {
        update.changed |= self.lift(&denial);
        // An NSEC already past its TTL denies nothing: never take live
        // rows away for it.
        if !denial.is_live() {
            return;
        }
        log::debug!(
            "mex: {} denies {} via NSEC ({} form, from {})",
            denial.service,
            browse::rtype_label(denial.rtype),
            denial.form.as_str(),
            denial.source
        );
        update.applied.push(denial.clone());
        self.denials.push(denial);
        update.changed = true;
    }

    /// Live denials of `service` as (address type, host or every host).
    pub(super) fn denied_types(&self, service: &str) -> Vec<(u16, Option<String>)> {
        self.denials
            .iter()
            .filter(|d| d.service == service && d.is_live())
            .map(|d| (d.rtype, d.host.clone()))
            .collect()
    }

    /// Whether a live denial keeps `rtype` addresses of `host` (lowercased)
    /// off `service`.
    pub(super) fn covers(&self, service: &str, rtype: u16, host: &str) -> bool {
        self.denials.iter().any(|d| d.covers(service, rtype, host))
    }

    /// Whether a live denial keeps this address row off `service`.
    pub(super) fn denies(&self, service: &str, rec: &browse::RawRecord) -> bool {
        matches!(rec.rtype, 1 | 28) && {
            let host = rec.name.trim_end_matches('.').to_ascii_lowercase();
            self.covers(service, rec.rtype, &host)
        }
    }

    /// Live address denials of one service, for the dump (#245).
    pub(super) fn dump(&self, service: &str) -> Vec<dump::DumpDenial> {
        self.denials
            .iter()
            .filter(|d| d.service == service && d.is_live())
            .map(|d| dump::DumpDenial {
                rtype_str: browse::rtype_label(d.rtype),
                form: d.form.as_str().to_string(),
                host: d.host.clone(),
                source: d.source.to_string(),
                ttl_remaining_secs: u64::from(d.ttl)
                    .saturating_sub(d.received_at.elapsed().as_secs()),
            })
            .collect()
    }

    /// Denials live for their NSEC's TTL and only while their service
    /// (or pending instance) does.
    pub(super) fn retain_owned_by(&mut self, owners: &HashSet<String>) {
        self.denials
            .retain(|d| d.is_live() && owners.contains(&d.service));
    }

    /// Keep an address no service may show, so its host header still
    /// lists it (deduplicated like rows: type, address, source).
    pub(super) fn withhold(&mut self, rec: &browse::RawRecord) {
        let host = rec.name.trim_end_matches('.').to_ascii_lowercase();
        let rows = self.withheld.entry(host).or_default();
        rows.retain(|r| !same_address_row(r, rec));
        if rec.ttl > 0 {
            rows.push(rec.clone());
        }
    }

    /// Drop a withheld copy of `rec` (same type, address, source).
    pub(super) fn forget_withheld(&mut self, rec: &browse::RawRecord) {
        let host = rec.name.trim_end_matches('.').to_ascii_lowercase();
        if let Some(rows) = self.withheld.get_mut(&host) {
            rows.retain(|r| !same_address_row(r, rec));
            if rows.is_empty() {
                self.withheld.remove(&host);
            }
        }
    }

    /// Withheld addresses of one host (lowercased).
    pub(super) fn withheld(&self, host: &str) -> impl Iterator<Item = &browse::RawRecord> {
        self.withheld.get(host).into_iter().flatten()
    }

    /// Every withheld address, of every host.
    pub(super) fn all_withheld(&self) -> impl Iterator<Item = &browse::RawRecord> {
        self.withheld.values().flatten()
    }

    /// Withheld addresses live for their TTL.
    pub(super) fn expire_withheld(&mut self) {
        self.withheld.retain(|_, rows| {
            rows.retain(|r| r.ttl > 0 && r.received_at.elapsed().as_secs() <= u64::from(r.ttl));
            !rows.is_empty()
        });
    }
}

/// Same withheld row: type, address, source and ingress link.
fn same_address_row(a: &browse::RawRecord, b: &browse::RawRecord) -> bool {
    a.rtype == b.rtype && a.rdata == b.rdata && a.source == b.source && a.ifindex == b.ifindex
}

impl App {
    /// Feed a response's NSEC records to the denials, then take each
    /// newly denied address type off its service (the rows stay as
    /// withheld addresses of their host).
    pub(super) fn ingest_address_denials(&mut self, ev: &browse::Event) {
        let instances = self.live_service_keys();
        let update = self.address_denials.ingest(ev, instances);
        for denial in &update.applied {
            let Some(svc) = self
                .services
                .iter_mut()
                .find(|s| service_key(&s.instance, &s.service_type) == denial.service())
            else {
                continue;
            };
            let mut withheld = Vec::new();
            svc.answers.retain(|r| {
                let owner = r.name.trim_end_matches('.').to_ascii_lowercase();
                let denied = denial.applies_to(r.rtype, &owner);
                if denied {
                    withheld.push(r.clone());
                }
                !denied
            });
            for rec in withheld {
                self.address_denials.withhold(&rec);
            }
        }
        if update.changed {
            self.touch();
        }
    }
}
