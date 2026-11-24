// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn unusable_interfaces_are_skipped() {
    fn iface(status: if_addrs::IfOperStatus, p2p: bool) -> if_addrs::Interface {
        if_addrs::Interface {
            name: "eth0".into(),
            addr: if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip: Ipv4Addr::new(192, 168, 1, 2),
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                prefixlen: 24,
                broadcast: None,
            }),
            index: Some(2),
            oper_status: status,
            is_p2p: p2p,
        }
    }
    use if_addrs::IfOperStatus as St;
    assert!(usable_interface(&iface(St::Up, false)));
    assert!(!usable_interface(&iface(St::Down, false)));
    assert!(!usable_interface(&iface(St::LowerLayerDown, false)));
    assert!(!usable_interface(&iface(St::Unknown, false)));
    assert!(!usable_interface(&iface(St::Dormant, false)));
    assert!(!usable_interface(&iface(St::Testing, false)));
    assert!(!usable_interface(&iface(St::NotPresent, false)));
    assert!(!usable_interface(&iface(St::Up, true)));
    assert!(!usable_interface(&iface(St::Unknown, true)));
}

#[test]
fn backfill_rescans_once_per_unknown_index() {
    use std::cell::Cell;
    use std::net::{IpAddr, Ipv4Addr};
    let scans = Cell::new(0);
    let scan = || {
        scans.set(scans.get() + 1);
        (
            HashMap::from([(7u32, "wlp13s0".to_string())]),
            HashMap::from([(
                7u32,
                vec![(
                    IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                    IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
                )],
            )]),
        )
    };
    let mut ifnames = HashMap::new();
    let mut subnets: SubnetMap = HashMap::new();
    let mut unknown = HashSet::new();
    // Miss + scan finds it: both maps backfilled for later packets.
    backfill_link(7, &mut ifnames, &mut subnets, &mut unknown, &scan);
    assert_eq!(ifnames.get(&7).map(String::as_str), Some("wlp13s0"));
    assert!(subnets.contains_key(&7));
    assert_eq!(scans.get(), 1);
    // Remembered from here on: no second scan for the same index.
    backfill_link(7, &mut ifnames, &mut subnets, &mut unknown, &scan);
    assert_eq!(scans.get(), 1);
    // Miss + absent from scan: one scan, stays unknown.
    backfill_link(9, &mut ifnames, &mut subnets, &mut unknown, &scan);
    assert_eq!(scans.get(), 2);
    assert!(unknown.contains(&9));
    assert!(!ifnames.contains_key(&9));
    assert!(!subnets.contains_key(&9));
}

#[test]
fn mdns_multicast_dest_matches_only_mdns_groups() {
    assert!(mdns_multicast_dest(&IpAddr::V4(Ipv4Addr::new(
        224, 0, 0, 251
    ))));
    assert!(mdns_multicast_dest(&MDNS_V6.into()));
    assert!(!mdns_multicast_dest(&IpAddr::V4(Ipv4Addr::new(
        224, 0, 0, 252
    ))));
    assert!(!mdns_multicast_dest(&IpAddr::V4(Ipv4Addr::new(
        192, 168, 1, 10
    ))));
}

#[test]
fn source_on_link_applies_subnet_mask() {
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    let subnets: SubnetMap = HashMap::from([
        (
            2u32,
            vec![(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 10)),
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0)),
            )],
        ),
        (
            3u32,
            vec![(
                IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 1)),
                IpAddr::V6(Ipv6Addr::new(0xffff, 0xfc00, 0, 0, 0, 0, 0, 0)),
            )],
        ),
    ]);
    // Same /24: local.
    assert!(source_on_link(
        &subnets,
        2,
        &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))
    ));
    // Different subnet: off-link, refuse.
    assert!(!source_on_link(
        &subnets,
        2,
        &IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5))
    ));
    // Same fe80::/10: local.
    assert!(source_on_link(
        &subnets,
        3,
        &IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2))
    ));
    // Global source against a link-local prefix: refuse.
    assert!(!source_on_link(
        &subnets,
        3,
        &IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1))
    ));
    // Unknown index and family mismatch fail closed.
    assert!(!source_on_link(
        &subnets,
        9,
        &IpAddr::V4(Ipv4Addr::new(192, 168, 1, 99))
    ));
    assert!(!source_on_link(
        &subnets,
        2,
        &IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 2))
    ));
}

#[test]
fn link_stats_lists_are_sorted_and_disjoint() {
    let stats = link_stats(None);
    let mut v4 = stats.v4.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    let mut sorted = v4.clone();
    sorted.sort();
    assert_eq!(v4, sorted);
    // Usable links are never reported as skipped/inactive.
    for name in &v4 {
        assert!(!stats.skipped.contains(name));
        assert!(!stats.inactive.contains(name));
    }
    v4 = stats.v6.iter().map(|(n, _)| n.clone()).collect::<Vec<_>>();
    sorted = v4.clone();
    sorted.sort();
    assert_eq!(v4, sorted);
}

#[test]
fn link_stats_selection_confines_usable_to_selected() {
    // Whatever this machine has, a selection must only ever report
    // selected names as usable and never as skipped: display and
    // transport join set cannot contradict each other.
    let sel = HashSet::from(["br0".to_string(), "eth0".to_string(), "lo".to_string()]);
    let stats = link_stats(Some(&sel));
    for (name, _) in &stats.v4 {
        assert!(sel.contains(name), "usable {name} not selected");
    }
    for (name, _) in &stats.v6 {
        assert!(sel.contains(name), "usable {name} not selected");
    }
    for name in &stats.skipped {
        assert!(!sel.contains(name), "selected {name} reported skipped");
    }
    let mut skipped = stats.skipped.clone();
    skipped.sort();
    assert_eq!(stats.skipped, skipped);
    let mut inactive = stats.inactive.clone();
    inactive.sort();
    assert_eq!(stats.inactive, inactive);
}

#[test]
fn selection_unset_allows_every_link() {
    assert!(interface_selected("br0", None));
    assert!(interface_selected("eth0", None));
    assert!(interface_selected("", None));
}

#[test]
fn selection_set_restricts_to_named_links() {
    let sel = HashSet::from(["br0".to_string()]);
    assert!(interface_selected("br0", Some(&sel)));
    assert!(!interface_selected("eth0", Some(&sel)));
    // Unmapped ingress never matches a selection: fail closed.
    assert!(!interface_selected("", Some(&sel)));
}

#[test]
fn join_candidate_explicit_selection_overrides_skip_policy() {
    let lo = HashSet::from(["lo".to_string()]);
    // Explicitly selected loopback joins when usable ...
    assert!(join_candidate("lo", true, Some(&lo)));
    // ... while unselected usable links do not.
    assert!(!join_candidate("eth0", true, Some(&lo)));
    // Unfiltered behavior is unchanged.
    assert!(!join_candidate("lo", true, None));
    assert!(join_candidate("eth0", true, None));
    // Down links never join: the periodic refresh picks them up when up.
    let br0 = HashSet::from(["br0".to_string()]);
    assert!(!join_candidate("br0", false, Some(&br0)));
    assert!(!join_candidate("eth0", false, None));
    // Container skips still apply without a filter.
    assert!(!join_candidate("docker0", true, None));
    assert!(!join_candidate("veth1234", true, None));
}

#[test]
fn validate_selection_accepts_known_names_deduped() {
    let available = HashSet::from(["br0".to_string(), "eth0".to_string()]);
    let got = validate_selection(
        &["br0".to_string(), "eth0".to_string(), "br0".to_string()],
        &available,
    )
    .unwrap();
    assert_eq!(got, HashSet::from(["br0".to_string(), "eth0".to_string()]));
}

#[test]
fn validate_selection_rejects_unknown_with_available_list() {
    let available = HashSet::from(["br0".to_string(), "eth0".to_string()]);
    let err = validate_selection(&["br0".to_string(), "nope".to_string()], &available).unwrap_err();
    let msg = err.to_string();
    assert!(msg.contains("'nope'"), "got: {msg}");
    assert!(msg.contains("br0, eth0"), "got: {msg}");
}

/// One if-addrs entry: `name` up (or down), not point-to-point, with
/// one address and its index.
fn iface(name: &str, addr: &str, index: u32, up: bool) -> if_addrs::Interface {
    let ip: IpAddr = addr.parse().unwrap();
    if_addrs::Interface {
        name: name.to_string(),
        addr: match ip {
            IpAddr::V4(ip) => if_addrs::IfAddr::V4(if_addrs::Ifv4Addr {
                ip,
                netmask: Ipv4Addr::new(255, 255, 255, 0),
                prefixlen: 24,
                broadcast: None,
            }),
            IpAddr::V6(ip) => if_addrs::IfAddr::V6(if_addrs::Ifv6Addr {
                ip,
                netmask: Ipv6Addr::from(u128::MAX << 64),
                prefixlen: 64,
                broadcast: None,
            }),
        },
        index: Some(index),
        oper_status: if up {
            if_addrs::IfOperStatus::Up
        } else {
            if_addrs::IfOperStatus::Down
        },
        is_p2p: false,
        #[cfg(windows)]
        adapter_name: String::new(),
    }
}

fn p2p(mut link: if_addrs::Interface) -> if_addrs::Interface {
    link.is_p2p = true;
    link
}

/// A host with every kind of link the classification tells apart.
fn host_links() -> Vec<if_addrs::Interface> {
    vec![
        // Two v4 and two link-local v6 addresses: joined once each.
        iface("eth0", "192.168.1.2", 2, true),
        iface("eth0", "192.168.1.3", 2, true),
        iface("eth0", "fe80::1", 2, true),
        iface("eth0", "fe80::2", 2, true),
        iface("eth0", "2001:db8::1", 2, true),
        // A link with only a global v6 address is not a v6 target.
        iface("eth2", "2001:db8::2", 6, true),
        // Down, and point-to-point: no multicast to join.
        iface("eth1", "10.0.0.2", 3, false),
        iface("eth1", "10.0.0.3", 3, false),
        p2p(iface("wg0", "10.9.0.1", 4, true)),
        // Skipped by policy unless selected.
        iface("lo", "127.0.0.1", 1, true),
        iface("docker0", "172.17.0.1", 5, true),
    ]
}

#[test]
fn link_stats_classify_every_kind_of_link() {
    let stats = link_stats_in(&host_links(), None);
    assert_eq!(
        stats.v4,
        [("eth0".to_string(), Ipv4Addr::new(192, 168, 1, 2))]
    );
    assert_eq!(stats.v6, [("eth0".to_string(), 2)]);
    assert_eq!(stats.skipped, ["docker0", "lo"]);
    assert_eq!(stats.inactive, ["eth1", "wg0"], "each named once");
}

#[test]
fn link_stats_selection_overrides_policy_but_not_usability() {
    let sel = HashSet::from(["lo".to_string(), "eth1".to_string()]);
    let stats = link_stats_in(&host_links(), Some(&sel));
    assert_eq!(stats.v4, [("lo".to_string(), Ipv4Addr::LOCALHOST)]);
    assert!(stats.v6.is_empty());
    // Unselected usable links are skipped; the selected but down link
    // waits in inactive for the rejoin refresh.
    assert_eq!(stats.skipped, ["docker0", "eth0", "eth2"]);
    assert_eq!(stats.inactive, ["eth1", "wg0"]);
}

#[test]
fn join_lists_take_one_address_per_usable_link() {
    let links = host_links();
    assert_eq!(
        v4_interfaces_in(&links, None),
        [("eth0".to_string(), Ipv4Addr::new(192, 168, 1, 2))]
    );
    assert_eq!(v6_interfaces_in(&links, None), [("eth0".to_string(), 2)]);
    let sel = HashSet::from(["eth1".to_string()]);
    assert!(
        v4_interfaces_in(&links, Some(&sel)).is_empty(),
        "eth1 is down"
    );
}

#[test]
fn available_interfaces_name_every_link_in_any_state() {
    // The selection universe: down, point-to-point and policy-skipped
    // links validate too, each name once.
    let names: HashSet<String> = ["eth0", "eth1", "eth2", "wg0", "lo", "docker0"]
        .map(String::from)
        .into();
    assert_eq!(available_interfaces_in(&host_links()), names);
    // The host listing: a single enumeration, so no race with link
    // changes between two scans.
    assert!(available_interfaces().iter().all(|n| !n.is_empty()));
}
