// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;
use std::net::SocketAddr;
use std::time::Duration;

mod analyze;
mod conflicts;
mod flush;
mod header;
mod naming;
mod questions;
mod rate;
mod records;
mod resolve;
mod responses;
mod scope;
mod ttl;

fn test_source() -> SocketAddr {
    "192.168.1.2:5353".parse().unwrap()
}

fn rec(name: &str, rtype: u16, rtype_str: &str, rdata: &str, ttl: u32, flush: bool) -> RawRecord {
    rec_with(
        name,
        rtype,
        rtype_str,
        rdata,
        ttl,
        flush,
        true,
        crate::browse::RecordSection::Answer,
    )
}

#[allow(clippy::too_many_arguments)]
fn rec_with(
    name: &str,
    rtype: u16,
    rtype_str: &str,
    rdata: &str,
    ttl: u32,
    flush: bool,
    dst_is_multicast: bool,
    section: crate::browse::RecordSection,
) -> RawRecord {
    RawRecord {
        name: name.to_string(),
        owner_labels: name
            .trim_end_matches('.')
            .split('.')
            .map(|label| label.as_bytes().to_vec())
            .collect(),
        ptr_target_labels: (rtype == 12).then(|| {
            rdata
                .trim_end_matches('.')
                .split('.')
                .map(|label| label.as_bytes().to_vec())
                .collect()
        }),
        rtype,
        rtype_str: rtype_str.to_string(),
        flush_bit: flush,
        qu: false,
        invalid_utf8: false,
        ttl,
        rdata: rdata.to_string(),
        wire: Vec::new(),
        source: test_source(),
        iface: String::new(),
        ifindex: 0,
        dst_is_multicast,
        section,
        received_at: Instant::now(),
        trigger: None,
        rdata_digest: None,
    }
}

fn aged(mut r: RawRecord, secs: u64) -> RawRecord {
    r.received_at = Instant::now()
        .checked_sub(Duration::from_secs(secs))
        .unwrap_or_else(Instant::now);
    r
}

fn analyze_service(
    instance: &str,
    service_type: &str,
    hostname: &str,
    answers: &[RawRecord],
) -> Vec<Anomaly> {
    analyze_service_sub(instance, service_type, hostname, answers, &[])
}

fn analyze_service_sub(
    instance: &str,
    service_type: &str,
    _hostname: &str,
    answers: &[RawRecord],
    subtypes: &[Vec<u8>],
) -> Vec<Anomaly> {
    let services = vec![ServiceView {
        instance,
        service_type,
        answers,
        subtypes,
        denied_address_types: Vec::new(),
    }];
    let snap = Snapshot {
        services,
        enum_answers: Vec::new(),
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: Vec::new(),
        device_names: HashMap::new(),
    };
    analyze(&snap)
}
