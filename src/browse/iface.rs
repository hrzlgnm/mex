// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

pub fn local_ips() -> HashSet<IpAddr> {
    let mut out = HashSet::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        out.insert(iface.addr.ip());
    }
    out
}

/// Snapshot of usable vs skipped links for the diagnostics view. Refreshed on
/// demand from `if_addrs` (same source as the listener joins), so the App
/// thread sees link changes without new thread communication.
#[derive(Debug, Clone, Default)]
pub struct LinkStats {
    /// Usable v4 links: (interface name, address).
    pub v4: Vec<(String, Ipv4Addr)>,
    /// Usable v6 links: (interface name, index).
    pub v6: Vec<(String, u32)>,
    /// Distinct names skipped by policy (`lo`/`docker`/`veth`), or
    /// excluded by an explicit interface selection.
    pub skipped: Vec<String>,
    /// Distinct names that are down or point-to-point (no multicast).
    pub inactive: Vec<String>,
}

/// Effective join set for the diagnostics view: usable links under the
/// default skip policy, or the selected usable links under an explicit
/// selection (which overrides the policy). Unselected usable links are
/// reported as skipped so the snapshot still enumerates every link.
pub fn link_stats(selection: Option<&HashSet<String>>) -> LinkStats {
    link_stats_in(&if_addrs::get_if_addrs().unwrap_or_default(), selection)
}

/// `link_stats` over a given if-addrs listing.
pub(super) fn link_stats_in(
    ifaces: &[if_addrs::Interface],
    selection: Option<&HashSet<String>>,
) -> LinkStats {
    let mut stats = LinkStats::default();
    let mut seen_v4 = HashSet::new();
    let mut seen_v6 = HashSet::new();
    let mut seen_skipped = HashSet::new();
    let mut seen_inactive = HashSet::new();
    for iface in ifaces {
        let usable = usable_interface(iface);
        if !join_candidate(&iface.name, usable, selection) {
            // Not joined: policy skip, selection exclusion (usable links
            // only), or unusable. A selected-but-down link lands in
            // inactive, visibly waiting for the rejoin refresh.
            if skipped_interface(&iface.name) || (usable && selection.is_some()) {
                if seen_skipped.insert(iface.name.clone()) {
                    stats.skipped.push(iface.name.clone());
                }
            } else if seen_inactive.insert(iface.name.clone()) {
                stats.inactive.push(iface.name.clone());
            }
            continue;
        }
        match &iface.addr {
            if_addrs::IfAddr::V4(v4) => {
                if seen_v4.insert(iface.name.clone()) {
                    stats.v4.push((iface.name.clone(), v4.ip));
                }
            }
            if_addrs::IfAddr::V6(v6) => {
                if v6.ip.to_string().starts_with('f') && seen_v6.insert(iface.name.clone()) {
                    stats
                        .v6
                        .push((iface.name.clone(), iface.index.unwrap_or(0)));
                }
            }
        }
    }
    stats.v4.sort_by(|a, b| a.0.cmp(&b.0));
    stats.v6.sort_by(|a, b| a.0.cmp(&b.0));
    stats.skipped.sort();
    stats.inactive.sort();
    stats
}

/// Per-link ingress data in one if-addrs pass: index → name plus
/// index → [(address, netmask)] for the RFC 6762 §11 locality test.
/// Unfiltered on purpose: locality labeling and subnet checks must see
/// every link, including ones skipped for multicast joins.
pub(super) type SubnetMap = HashMap<u32, Vec<(IpAddr, IpAddr)>>;

pub(super) fn link_maps() -> (HashMap<u32, String>, SubnetMap) {
    let mut names = HashMap::new();
    let mut subnets: SubnetMap = HashMap::new();
    for iface in if_addrs::get_if_addrs().unwrap_or_default() {
        let Some(idx) = iface.index else { continue };
        names.entry(idx).or_insert_with(|| iface.name.clone());
        let (addr, mask) = match iface.addr {
            if_addrs::IfAddr::V4(v4) => (IpAddr::V4(v4.ip), IpAddr::V4(v4.netmask)),
            if_addrs::IfAddr::V6(v6) => (IpAddr::V6(v6.ip), IpAddr::V6(v6.netmask)),
        };
        subnets.entry(idx).or_default().push((addr, mask));
    }
    (names, subnets)
}

/// Fill gaps in the cached link maps: the interface may have appeared
/// since the last 10s refresh. Re-queries if-addrs once per unknown
/// index (remembered in `unknown` until the next refresh) so a
/// permanently unmapped index costs one scan, not one per packet.
/// The scan is injected for testing; the listener passes `link_maps`.
pub(super) fn backfill_link(
    ifindex: u32,
    ifnames: &mut HashMap<u32, String>,
    subnets: &mut SubnetMap,
    unknown: &mut HashSet<u32>,
    scan: &dyn Fn() -> (HashMap<u32, String>, SubnetMap),
) {
    if !unknown.insert(ifindex) {
        return;
    }
    let (names, nets) = scan();
    if let Some(name) = names.get(&ifindex) {
        ifnames.insert(ifindex, name.clone());
    }
    if let Some(net) = nets.get(&ifindex) {
        subnets.insert(ifindex, net.clone());
    }
}

/// The two mDNS link-local multicast destinations (RFC 6762 §3).
pub(super) fn mdns_multicast_dest(dst: &IpAddr) -> bool {
    *dst == IpAddr::V4(MDNS_V4) || *dst == IpAddr::V6(MDNS_V6)
}

/// RFC 6762 §11 locality test for unicast-destination packets: the
/// source shares a local subnet ((I&M)==(P&M)) on the ingress link.
/// Unknown links and family mismatches fail closed (refuse).
pub(super) fn source_on_link(subnets: &SubnetMap, ifindex: u32, src: &IpAddr) -> bool {
    let Some(nets) = subnets.get(&ifindex) else {
        return false;
    };
    nets.iter().any(|(addr, mask)| match (addr, mask, src) {
        (IpAddr::V4(i), IpAddr::V4(m), IpAddr::V4(p)) => {
            u32::from_be_bytes(i.octets()) & u32::from_be_bytes(m.octets())
                == u32::from_be_bytes(p.octets()) & u32::from_be_bytes(m.octets())
        }
        (IpAddr::V6(i), IpAddr::V6(m), IpAddr::V6(p)) => {
            u128::from_be_bytes(i.octets()) & u128::from_be_bytes(m.octets())
                == u128::from_be_bytes(p.octets()) & u128::from_be_bytes(m.octets())
        }
        _ => false,
    })
}

/// Whether an interface is usable for mDNS: it must be operationally
/// up, and point-to-point links are skipped (they have no multicast
/// group to browse). Sourced from if-addrs so this stays cross-platform.
pub(super) fn usable_interface(iface: &if_addrs::Interface) -> bool {
    !iface.is_p2p() && iface.is_oper_up()
}

pub(super) fn skipped_interface(name: &str) -> bool {
    name == "lo" || name.starts_with("docker") || name.starts_with("veth")
}

/// All OS interface names in any state (up, down, point-to-point): the
/// validation universe for an explicit selection. Down links validate
/// fine and are picked up by the periodic rejoin once they come up.
pub fn available_interfaces() -> HashSet<String> {
    if_addrs::get_if_addrs()
        .unwrap_or_default()
        .iter()
        .map(|i| i.name.clone())
        .collect()
}

/// Validate an explicit `-i/--interfaces` selection: every name must
/// exist, otherwise abort listing the sorted available names (same
/// shape as the sibling browser). Returns the deduped set.
pub fn validate_selection(
    requested: &[String],
    available: &HashSet<String>,
) -> Result<HashSet<String>> {
    let mut sorted: Vec<&String> = available.iter().collect();
    sorted.sort();
    for name in requested {
        if !available.contains(name) {
            anyhow::bail!(
                "Interface '{name}' not found. Available interfaces: {}",
                sorted
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
    }
    Ok(requested.iter().cloned().collect())
}

/// Whether ingress from `name` is kept under an explicit selection:
/// unset keeps every link, set keeps only named ones. Unmapped ingress
/// (empty name) fails closed under a selection.
pub(super) fn interface_selected(name: &str, selection: Option<&HashSet<String>>) -> bool {
    selection.is_none_or(|sel| sel.contains(name))
}

/// Whether a link is a multicast-join candidate: an explicit selection
/// overrides the loopback/container skip policy (user intent wins) but
/// still requires the link to be usable; down links wait for the
/// periodic refresh instead of erroring.
pub(super) fn join_candidate(
    name: &str,
    usable: bool,
    selection: Option<&HashSet<String>>,
) -> bool {
    if !usable {
        return false;
    }
    match selection {
        Some(sel) => sel.contains(name),
        None => !skipped_interface(name),
    }
}

pub(super) fn v4_interfaces(selection: Option<&HashSet<String>>) -> Vec<(String, Ipv4Addr)> {
    v4_interfaces_in(&if_addrs::get_if_addrs().unwrap_or_default(), selection)
}

/// `v4_interfaces` over a given if-addrs listing.
pub(super) fn v4_interfaces_in(
    ifaces: &[if_addrs::Interface],
    selection: Option<&HashSet<String>>,
) -> Vec<(String, Ipv4Addr)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for iface in ifaces {
        if !join_candidate(&iface.name, usable_interface(iface), selection) {
            continue;
        }
        if let if_addrs::IfAddr::V4(v4) = &iface.addr {
            // Join once per interface: extra addresses share the group.
            if seen.insert(iface.name.clone()) {
                out.push((iface.name.clone(), v4.ip));
            }
        }
    }
    out
}

pub(super) fn v6_interfaces(selection: Option<&HashSet<String>>) -> Vec<(String, u32)> {
    v6_interfaces_in(&if_addrs::get_if_addrs().unwrap_or_default(), selection)
}

/// `v6_interfaces` over a given if-addrs listing.
pub(super) fn v6_interfaces_in(
    ifaces: &[if_addrs::Interface],
    selection: Option<&HashSet<String>>,
) -> Vec<(String, u32)> {
    let mut out = Vec::new();
    let mut seen = HashSet::new();
    for iface in ifaces {
        if !join_candidate(&iface.name, usable_interface(iface), selection) {
            continue;
        }
        if let if_addrs::IfAddr::V6(v6) = &iface.addr {
            // Join once per interface: extra addresses share the group.
            if v6.ip.to_string().starts_with('f') && seen.insert(iface.name.clone()) {
                out.push((iface.name.clone(), iface.index.unwrap_or(0)));
            }
        }
    }
    out
}
