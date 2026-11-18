// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn port_zero_never_flagged() {
    let answers = vec![rec(
        "My._http._tcp.local.",
        33,
        "SRV",
        "0 0 0 myhost.local.",
        120,
        true,
    )];
    let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::SrvTarget));
}

#[test]
fn srv_target_outside_local_is_info() {
    let answers = vec![rec(
        "My._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 example.com.",
        120,
        true,
    )];
    let found = analyze_service("My", "_http._tcp.local", "example.com.", &answers);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::SrvTarget)
        .expect("expected srv-target");
    assert_eq!(item.severity, Severity::Info);
    assert!(
        item.message.contains("needs unicast DNS"),
        "got: {}",
        item.message
    );
}

#[test]
fn txt_valueless_empty_and_missing_equals_quiet() {
    let answers = vec![
        rec("X._http._tcp.local.", 16, "TXT", "flag-only", 120, true),
        rec("X._http._tcp.local.", 16, "TXT", "", 120, true),
        rec("X._http._tcp.local.", 16, "TXT", "k=v; bare", 120, true),
    ];
    let found = analyze_service("X", "_http._tcp.local", "", &answers);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TxtOversize));
}

#[test]
fn txt_oversize_flagged() {
    let big = "k=".to_string() + &"x".repeat(1400);
    let answers = vec![rec("X._http._tcp.local.", 16, "TXT", &big, 120, true)];
    let found = analyze_service("X", "_http._tcp.local", "", &answers);
    assert!(found.iter().any(|a| a.kind == AnomalyKind::TxtOversize));
}

#[test]
fn txt_oversize_measures_wire_rdata() {
    // Non-UTF-8 values display as 3-byte U+FFFD each: the lossy
    // display string tops 1300 bytes while the wire RDATA does not.
    let value = vec![0xffu8; 240];
    let strings: Vec<&[u8]> = vec![&value; 5];
    let mut small = rec(
        "X._http._tcp.local.",
        16,
        "TXT",
        &"\u{fffd}".repeat(1200),
        4500,
        true,
    );
    small.wire = txt_wire("X._http._tcp.local.", &strings);
    let found = analyze_service("X", "_http._tcp.local", "", &[small]);
    assert!(
        !found.iter().any(|a| a.kind == AnomalyKind::TxtOversize),
        "1205-byte RDATA stays under the limit, got: {found:?}"
    );

    // Many short strings: the length bytes push RDATA over the limit
    // although the joined display string is shorter.
    let short = *b"k=v";
    let strings: Vec<&[u8]> = vec![&short; 330];
    let mut big = rec(
        "X._http._tcp.local.",
        16,
        "TXT",
        &vec!["k=v"; 330].join("; ")[..1290],
        4500,
        true,
    );
    big.wire = txt_wire("X._http._tcp.local.", &strings);
    let found = analyze_service("X", "_http._tcp.local", "", &[big]);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::TxtOversize)
        .expect("1320-byte RDATA is oversize");
    assert_eq!(item.message, "TXT 1320B, max 1300B");
}

#[test]
fn srv_root_target_is_service_unavailable_note() {
    // RFC 2782: "." means the service is decidedly not available.
    let answers = vec![rec("X._http._tcp.local.", 33, "SRV", "0 0 0 .", 120, true)];
    let found = analyze_service("X", "_http._tcp.local", "", &answers);
    let item = found
        .iter()
        .find(|a| a.kind == AnomalyKind::SrvTarget)
        .expect("root target note");
    assert_eq!(item.severity, Severity::Info);
    assert_eq!((item.rfc, item.requirement), ("RFC 2782", ""));
    assert!(item.message.contains("not available"), "{}", item.message);
    assert!(!found
        .iter()
        .any(|a| a.kind == AnomalyKind::UnresolvedSrvTarget));
}

#[test]
fn srv_rejects_non_numeric_fields() {
    let answers = vec![rec(
        "My._http._tcp.local.",
        33,
        "SRV",
        "fast quick 80 myhost.local.",
        120,
        true,
    )];
    let found = analyze_service("My", "_http._tcp.local", "myhost.local.", &answers);
    assert!(found.iter().any(|a| a.kind == AnomalyKind::SrvTarget));
}

#[test]
fn srv_rejects_empty_dns_label_in_target() {
    let answers = vec![rec(
        "My._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 foo..local.",
        120,
        true,
    )];
    let found = analyze_service("My", "_http._tcp.local", "foo..local.", &answers);
    assert!(found.iter().any(|a| a.kind == AnomalyKind::SrvTarget));
}

#[test]
fn txt_wire_overhead_alone_is_quiet() {
    let mut r = rec("X._http._tcp.local.", 16, "TXT", "k=v", 120, true);
    r.wire = vec![0u8; 1400];
    let found = analyze_service("X", "_http._tcp.local", "", &[r]);
    assert!(!found.iter().any(|a| a.kind == AnomalyKind::TxtOversize));
}

/// Standalone TXT wire record: uncompressed owner, header, then
/// `strings` as length-prefixed character strings.
fn txt_wire(owner: &str, strings: &[&[u8]]) -> Vec<u8> {
    let mut wire = Vec::new();
    for label in owner.trim_end_matches('.').split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
    wire.extend_from_slice(&[0, 16, 0x80, 1, 0, 0, 0x11, 0x94]);
    let rdata: Vec<u8> = strings
        .iter()
        .flat_map(|s| std::iter::once(s.len() as u8).chain(s.iter().copied()))
        .collect();
    wire.extend_from_slice(&(rdata.len() as u16).to_be_bytes());
    wire.extend_from_slice(&rdata);
    wire
}
