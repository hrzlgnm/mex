// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! `conflicting-answers` input filtering, at the analyzer level.

use super::*;

fn from(mut r: RawRecord, source: &str) -> RawRecord {
    r.source = source.parse().unwrap();
    r
}

fn conflicts(records: &[RawRecord]) -> Vec<Anomaly> {
    let snap = Snapshot {
        services: Vec::new(),
        enum_answers: Vec::new(),
        pending_hosts: HashSet::new(),
        questions: Vec::new(),
        sightings: Vec::new(),
        host_addresses: vec![HostAddressView {
            host: "h.local".to_string(),
            records: records.iter().collect(),
        }],
        device_names: HashMap::new(),
    };
    analyze(&snap)
        .into_iter()
        .filter(|a| a.kind == AnomalyKind::ConflictingAnswers)
        .collect()
}

#[test]
fn only_live_address_records_take_part() {
    let records = [
        from(
            rec("h.local.", 1, "A", "192.168.1.10", 120, true),
            "192.168.1.20:5353",
        ),
        from(
            rec("h.local.", 1, "A", "192.168.1.11", 120, true),
            "192.168.1.30:5353",
        ),
        // A goodbye and a non-address record add no responder.
        from(
            rec("h.local.", 1, "A", "10.0.0.1", 0, true),
            "192.168.1.40:5353",
        ),
        // Disagreeing non-address records are no address conflict.
        from(
            rec("h.local.", 16, "TXT", "x=1", 120, false),
            "192.168.1.50:5353",
        ),
        from(
            rec("h.local.", 16, "TXT", "x=2", 120, false),
            "192.168.1.60:5353",
        ),
    ];
    let found = conflicts(&records);
    assert_eq!(found.len(), 1);
    let sources: Vec<_> = found[0]
        .responders
        .iter()
        .flat_map(|r| r.sources.clone())
        .collect();
    assert_eq!(sources, ["192.168.1.20:5353", "192.168.1.30:5353"]);
}

#[test]
fn unparsable_address_rdata_is_compared_as_text() {
    // The rdata of an address row is always an address in practice;
    // should one not parse, it still counts, verbatim, instead of
    // being dropped or failing the check.
    let records = [
        from(
            rec("h.local.", 1, "A", "192.168.1.10", 120, true),
            "192.168.1.20:5353",
        ),
        from(
            rec("h.local.", 1, "A", " not-an-ip ", 120, true),
            "192.168.1.30:5353",
        ),
    ];
    let found = conflicts(&records);
    assert_eq!(found.len(), 1);
    let addresses: Vec<_> = found[0]
        .responders
        .iter()
        .flat_map(|r| r.addresses.clone())
        .collect();
    assert_eq!(addresses, ["192.168.1.10", "not-an-ip"]);
}
