// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Device names behind source addresses (#246): which announced host
//! owns the address a packet came from. Derived on demand from live
//! A/AAAA records; never feeds the analyzer, so finding identity stays
//! keyed on raw source strings.

use std::collections::HashSet;
use std::net::{IpAddr, Ipv6Addr, SocketAddr};

use crate::browse::RawRecord;

/// Live address announcements: (address, owner name, announcing IP).
pub struct AddressBook {
    entries: Vec<(IpAddr, String, IpAddr)>,
    /// Dedup for `entries`: a book is built twice per frame, so adding
    /// must stay linear in the record count.
    seen: HashSet<(IpAddr, String, IpAddr)>,
    /// Hosts-pane group keys: preferred when several names tie.
    host_keys: HashSet<String>,
}

/// The device a source address resolves to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceName {
    /// Every candidate owner name (no root dot), preferred first.
    pub names: Vec<String>,
    /// Matched by IPv6 interface ID rather than exactly.
    pub inferred: bool,
}

impl DeviceName {
    /// Short display form: the preferred name's first label (`fritz` for
    /// `fritz.box`, `FritzBoxRepeater` for `FritzBoxRepeater.local`),
    /// `~`-prefixed when inferred.
    pub fn display(&self) -> String {
        let name = self.names.first().map(String::as_str).unwrap_or_default();
        // Names are in presentation form: the first label, escapes dropped.
        let short = crate::browse::presentation_labels(name)
            .into_iter()
            .next()
            .unwrap_or_default();
        if self.inferred {
            format!("~{short}")
        } else {
            short.to_string()
        }
    }

    /// Host id (`anomalies::host_id` form) of the preferred name.
    pub fn host_id(&self) -> String {
        crate::anomalies::host_id(self.names.first().map(String::as_str).unwrap_or_default())
    }
}

impl AddressBook {
    pub fn new(host_keys: HashSet<String>) -> Self {
        Self {
            entries: Vec::new(),
            seen: HashSet::new(),
            host_keys,
        }
    }

    /// Take a record into the book if it is a live A/AAAA announcement.
    pub fn add(&mut self, rec: &RawRecord) {
        if !matches!(rec.rtype, 1 | 28) || rec.ttl == 0 {
            return;
        }
        if rec.received_at.elapsed().as_secs() > u64::from(rec.ttl) {
            return;
        }
        let Ok(addr) = rec.rdata.trim().parse::<IpAddr>() else {
            return;
        };
        let owner = rec.name.trim_end_matches('.').to_string();
        if owner.is_empty() {
            return;
        }
        let entry = (addr, owner, rec.source.ip());
        if self.seen.insert(entry.clone()) {
            self.entries.push(entry);
        }
    }

    /// Device behind a source IP (port and zone ignored): an exact
    /// match first, then, for IPv6 link-local sources only, an
    /// interface-ID match against global/ULA AAAA (inferred). Names
    /// announced by the source itself win over third-party (proxy)
    /// announcements.
    pub fn resolve(&self, ip: IpAddr) -> Option<DeviceName> {
        let exact: Vec<&(IpAddr, String, IpAddr)> =
            self.entries.iter().filter(|(a, _, _)| *a == ip).collect();
        if !exact.is_empty() {
            return Some(self.rank(ip, exact, false));
        }
        let IpAddr::V6(v6) = ip else {
            return None;
        };
        if !is_link_local(v6) {
            return None;
        }
        let iid = interface_id(v6);
        let inferred: Vec<&(IpAddr, String, IpAddr)> = self
            .entries
            .iter()
            .filter(|(a, _, _)| match a {
                IpAddr::V6(a) => is_global_or_ula(*a) && interface_id(*a) == iid,
                IpAddr::V4(_) => false,
            })
            .collect();
        if inferred.is_empty() {
            None
        } else {
            Some(self.rank(ip, inferred, true))
        }
    }

    /// Device behind a source label as findings and rows carry it
    /// (`1.2.3.4:5353`, `…@eth0`, `[fe80::1%2]:5353`, `[fe80::1]:5353%eth0`).
    pub fn resolve_label(&self, label: &str) -> Option<DeviceName> {
        self.resolve(parse_source_ip(label)?)
    }

    /// Order candidates: the source's own announcements first, then
    /// Hosts-pane group keys, `.local` names, alphabetical.
    fn rank(
        &self,
        source: IpAddr,
        found: Vec<&(IpAddr, String, IpAddr)>,
        inferred: bool,
    ) -> DeviceName {
        let mut ranked: Vec<(bool, bool, bool, String, String)> = Vec::new();
        for (_, owner, announcer) in found {
            let key = crate::anomalies::host_id(owner);
            let own = *announcer == source;
            if let Some(existing) = ranked.iter_mut().find(|r| r.3 == key) {
                // Same name from several announcers: own announcement wins.
                existing.0 &= !own;
                continue;
            }
            ranked.push((
                !own,
                !self.host_keys.contains(&key),
                !crate::browse::is_local_name(owner),
                key,
                owner.clone(),
            ));
        }
        ranked.sort();
        DeviceName {
            names: ranked.into_iter().map(|r| r.4).collect(),
            inferred,
        }
    }
}

/// IP of a source label, ignoring the port and any `@iface` / `%iface`
/// suffix.
pub fn parse_source_ip(label: &str) -> Option<IpAddr> {
    let label = label.trim();
    if let Ok(sa) = label.parse::<SocketAddr>() {
        return Some(sa.ip());
    }
    if let Ok(ip) = label.parse::<IpAddr>() {
        return Some(ip);
    }
    // Interface suffix after the port: `addr:port@iface`, `[v6]:port%iface`.
    for sep in ['@', '%'] {
        if let Some(at) = label.rfind(sep) {
            if !label[at..].contains(']') {
                if let Ok(sa) = label[..at].parse::<SocketAddr>() {
                    return Some(sa.ip());
                }
            }
        }
    }
    None
}

fn is_link_local(a: Ipv6Addr) -> bool {
    a.segments()[0] & 0xffc0 == 0xfe80
}

fn is_global_or_ula(a: Ipv6Addr) -> bool {
    !is_link_local(a) && !a.is_loopback() && !a.is_multicast() && !a.is_unspecified()
}

fn interface_id(a: Ipv6Addr) -> u64 {
    (u128::from(a) & u128::from(u64::MAX)) as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_labels_parse_to_their_ip() {
        let v4: IpAddr = "192.168.178.109".parse().unwrap();
        let v6: IpAddr = "fe80::ca0e:14ff:feff:416".parse().unwrap();
        assert_eq!(parse_source_ip("192.168.178.109:5353"), Some(v4));
        assert_eq!(parse_source_ip("192.168.178.109:5353@enp0s25"), Some(v4));
        assert_eq!(
            parse_source_ip("[fe80::ca0e:14ff:feff:416%2]:5353"),
            Some(v6)
        );
        assert_eq!(
            parse_source_ip("[fe80::ca0e:14ff:feff:416]:5353%enp0s25"),
            Some(v6)
        );
        assert_eq!(parse_source_ip("self"), None);
    }
}
