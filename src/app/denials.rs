use super::*;

impl App {
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
    pub(super) fn ingest_address_denials(&mut self, ev: &browse::Event) {
        let srvs: Vec<(String, String)> = ev
            .answers
            .iter()
            .filter(|r| r.rtype == 33 && r.ttl > 0)
            .filter_map(|r| {
                let target = srv_target(&r.rdata)?.to_lowercase();
                Some((r.name.trim_end_matches('.').to_lowercase(), target))
            })
            .collect();
        // This packet's SRVs name instances too (they are filed next).
        let mut instances = self.live_service_keys();
        instances.extend(srvs.iter().map(|(service, _)| service.clone()));
        // ...and so do its PTR targets and TXT owners (an instance NSEC
        // can arrive with the PTR before any SRV).
        for r in ev.answers.iter().filter(|r| r.ttl > 0) {
            match r.rtype {
                12 if !is_enum_name(r.name.trim_end_matches('.')) => {
                    instances.insert(r.rdata.trim_end_matches('.').to_lowercase());
                }
                16 => {
                    instances.insert(r.name.trim_end_matches('.').to_lowercase());
                }
                _ => {}
            }
        }
        for nsec in ev.answers.iter().filter(|r| r.rtype == 47) {
            let owner = nsec.name.trim_end_matches('.').to_lowercase();
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
                let before = self.address_denials.len();
                self.address_denials.retain(|d| {
                    d.host.as_deref() != Some(owner.as_str())
                        && !(d.host.is_none() && d.service == owner)
                });
                if self.address_denials.len() != before {
                    self.touch();
                }
                continue;
            }
            for (service, _) in srvs.iter().filter(|(_, target)| *target == owner) {
                for rtype in [1, 28] {
                    let d = denial(service, rtype, Some(&owner), DenialForm::Rfc);
                    if address.contains(&rtype) {
                        self.lift_denial(&d);
                    } else {
                        self.apply_denial(d);
                    }
                }
            }
            if instances.contains(&owner) {
                let inverted = !address.is_empty() && !other;
                for rtype in [1, 28] {
                    let d = denial(&owner, rtype, None, DenialForm::Legacy);
                    if inverted && address.contains(&rtype) {
                        self.apply_denial(d);
                    } else {
                        self.lift_denial(&d);
                    }
                }
            }
        }
    }

    /// Drop any denial with the same identity (service, type, host).
    pub(super) fn lift_denial(&mut self, denial: &AddressDenial) {
        let before = self.address_denials.len();
        self.address_denials.retain(|d| {
            !(d.service == denial.service && d.rtype == denial.rtype && d.host == denial.host)
        });
        if self.address_denials.len() != before {
            self.touch();
        }
    }

    /// Record (or refresh) one denial, and take matching address rows
    /// back off its service.
    pub(super) fn apply_denial(&mut self, denial: AddressDenial) {
        self.lift_denial(&denial);
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
        if let Some(svc) = self
            .services
            .iter_mut()
            .find(|s| service_key(&s.instance, &s.service_type) == denial.service)
        {
            let mut withheld = Vec::new();
            svc.answers.retain(|r| {
                let owner = r.name.trim_end_matches('.').to_lowercase();
                let denied = denial.applies_to(r.rtype, &owner);
                if denied {
                    withheld.push(r.clone());
                }
                !denied
            });
            for rec in withheld {
                self.withhold_address(&rec);
            }
        }
        self.address_denials.push(denial);
        self.touch();
    }

    /// Live denials of `service` as (address type, host or every host).
    pub(super) fn denied_types(&self, service: &str) -> Vec<(u16, Option<String>)> {
        self.address_denials
            .iter()
            .filter(|d| d.service == service && d.is_live())
            .map(|d| (d.rtype, d.host.clone()))
            .collect()
    }

    /// Whether a live denial keeps this address row off `service`.
    pub(super) fn address_denied(&self, service: &str, rec: &browse::RawRecord) -> bool {
        matches!(rec.rtype, 1 | 28) && {
            let host = rec.name.trim_end_matches('.').to_lowercase();
            self.address_denials
                .iter()
                .any(|d| d.covers(service, rec.rtype, &host))
        }
    }

    /// Drop a withheld copy of `rec` (same type, address, source).
    pub(super) fn forget_withheld(&mut self, rec: &browse::RawRecord) {
        let host = rec.name.trim_end_matches('.').to_lowercase();
        if let Some(rows) = self.withheld_addrs.get_mut(&host) {
            rows.retain(|r| {
                !(r.rtype == rec.rtype
                    && r.rdata == rec.rdata
                    && r.source == rec.source
                    && r.ifindex == rec.ifindex)
            });
            if rows.is_empty() {
                self.withheld_addrs.remove(&host);
            }
        }
    }

    /// Keep an address no service may show, so its host header still
    /// lists it (deduplicated like rows: type, address, source).
    pub(super) fn withhold_address(&mut self, rec: &browse::RawRecord) {
        let host = rec.name.trim_end_matches('.').to_lowercase();
        let rows = self.withheld_addrs.entry(host).or_default();
        rows.retain(|r| {
            !(r.rtype == rec.rtype
                && r.rdata == rec.rdata
                && r.source == rec.source
                && r.ifindex == rec.ifindex)
        });
        if rec.ttl > 0 {
            rows.push(rec.clone());
        }
    }
}
