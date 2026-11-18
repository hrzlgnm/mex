// --- NSEC address denials (#245) ---

use super::*;

#[test]
fn rfc_nsec_with_srv_denies_absent_type_for_that_service_only() {
    let mut app = knulp_app();
    // zeroconf: SRV + A + hostname NSEC [A] in one response.
    app.ingest_event(&packet(vec![
        srv_on_knulp(DACP),
        a_knulp(),
        raw_record("knulp.local.", 47, "NSEC", "knulp.local. A", 120),
    ]));
    assert!(rows_of(&app, DACP).contains(&1), "A stays");
    assert!(
        !rows_of(&app, DACP).contains(&28),
        "earlier AAAA taken back"
    );
    assert!(rows_of(&app, SMB).contains(&28), "sibling keeps its AAAA");
    // A later AAAA is not filed on _dacp either.
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::2", 120),
    );
    assert!(!rows_of(&app, DACP).contains(&28));
    assert!(rows_of(&app, SMB).contains(&28));
    // The NSEC row itself stays visible, and the host still lists v6.
    assert!(rows_of(&app, DACP).contains(&47));
    assert!(app
        .host_addresses("knulp.local")
        .iter()
        .any(|a| a == "fd00::1"));
}

#[test]
fn hostname_nsec_without_srv_in_packet_denies_nothing() {
    let mut app = knulp_app();
    app.ingest_event(&packet(vec![
        a_knulp(),
        raw_record("knulp.local.", 47, "NSEC", "knulp.local. A", 120),
    ]));
    assert!(rows_of(&app, DACP).contains(&28));
    assert!(rows_of(&app, SMB).contains(&28));
}

#[test]
fn legacy_instance_nsec_denies_listed_types_and_is_flagged() {
    let mut app = knulp_app();
    ingest(
        &mut app,
        &raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 120),
    );
    assert!(!rows_of(&app, DACP).contains(&28));
    assert!(rows_of(&app, SMB).contains(&28));
    let found: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.kind == anomalies::AnomalyKind::NsecInvertedBitmap)
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].severity, anomalies::Severity::Info);
    assert_eq!(found[0].service, "iTunes_Ctrl._dacp._tcp.local");
}

#[test]
fn compliant_instance_nsec_denies_nothing() {
    let mut app = knulp_app();
    ingest(
        &mut app,
        &raw_record(
            DACP,
            47,
            "NSEC",
            "iTunes_Ctrl._dacp._tcp.local. TXT SRV",
            120,
        ),
    );
    assert!(rows_of(&app, DACP).contains(&28));
    assert!(!app
        .anomalies()
        .iter()
        .any(|a| a.kind == anomalies::AnomalyKind::NsecInvertedBitmap));
}

#[test]
fn goodbye_lifts_the_denial_and_the_next_aaaa_files_again() {
    let mut app = knulp_app();
    let legacy = |ttl| raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", ttl);
    ingest(&mut app, &legacy(120));
    assert!(!rows_of(&app, DACP).contains(&28));
    app.ingest_event(&packet(vec![legacy(0)]));
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::3", 120),
    );
    assert!(
        rows_of(&app, DACP).contains(&28),
        "files again after the goodbye"
    );
}

#[test]
fn expired_denial_stops_applying() {
    let mut app = knulp_app();
    let mut nsec = raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 1);
    nsec.received_at = Instant::now() - Duration::from_secs(5);
    app.ingest_event(&packet(vec![nsec]));
    app.evict_expired();
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::4", 120),
    );
    assert!(rows_of(&app, DACP).contains(&28));
}

#[test]
fn denied_type_drives_no_interest_unless_a_sibling_wants_it() {
    let mut app = knulp_app();
    let denial = |inst: &str| {
        let owner = inst.trim_end_matches('.');
        raw_record(inst, 47, "NSEC", &format!("{owner}. AAAA"), 120)
    };
    ingest(&mut app, &denial(DACP));
    let wants_aaaa = |app: &App| {
        app.desired_continuous()
            .contains_key(&("knulp.local".to_string(), 28))
    };
    assert!(wants_aaaa(&app), "_smb still wants knulp AAAA");
    ingest(&mut app, &denial(SMB));
    assert!(!wants_aaaa(&app), "no service wants it any more");
    assert!(app
        .desired_continuous()
        .contains_key(&("knulp.local".to_string(), 1)));
}

#[test]
fn ipv4_only_service_with_live_a_is_not_unresolved() {
    let mut app = knulp_app();
    ingest(&mut app, &a_knulp());
    ingest(
        &mut app,
        &raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 120),
    );
    assert!(!app.anomalies().iter().any(|a| {
        a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget
            && a.service == "iTunes_Ctrl._dacp._tcp.local"
    }));
}

#[test]
fn dump_lists_denials_and_omits_denied_rows() {
    let mut app = knulp_app();
    ingest(
        &mut app,
        &raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 120),
    );
    let dump = app.state_dump();
    let dacp = dump
        .services
        .iter()
        .find(|s| s.instance == "iTunes_Ctrl")
        .expect("dumped");
    assert!(!dacp.answers.iter().any(|r| r.rtype == 28));
    assert_eq!(dacp.address_denials.len(), 1);
    assert_eq!(dacp.address_denials[0].rtype_str, "AAAA");
    assert_eq!(dacp.address_denials[0].form, "legacy");
    let smb = dump
        .services
        .iter()
        .find(|s| s.instance == "KNULP")
        .unwrap();
    assert!(smb.address_denials.is_empty());
}

#[test]
fn rfc_goodbye_lifts_without_a_live_srv_in_the_packet() {
    let mut app = knulp_app();
    app.ingest_event(&packet(vec![
        srv_on_knulp(DACP),
        raw_record("knulp.local.", 47, "NSEC", "knulp.local. A", 120),
    ]));
    assert!(!rows_of(&app, DACP).contains(&28));
    // A lone NSEC goodbye (no SRV in its packet) still lifts it.
    app.ingest_event(&packet(vec![raw_record(
        "knulp.local.",
        47,
        "NSEC",
        "knulp.local. A",
        0,
    )]));
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::5", 120),
    );
    assert!(rows_of(&app, DACP).contains(&28));
}

#[test]
fn newer_nsec_bitmap_replaces_the_denial() {
    let mut app = knulp_app();
    let nsec = |types: &str| {
        raw_record(
            "knulp.local.",
            47,
            "NSEC",
            &format!("knulp.local. {types}"),
            120,
        )
    };
    app.ingest_event(&packet(vec![srv_on_knulp(DACP), nsec("A")]));
    assert!(!rows_of(&app, DACP).contains(&28));
    // The host gained IPv6: the new bitmap lists AAAA, lifting it.
    app.ingest_event(&packet(vec![srv_on_knulp(DACP), nsec("A AAAA")]));
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::6", 120),
    );
    assert!(rows_of(&app, DACP).contains(&28));
    // Legacy form: a compliant instance NSEC lifts its denial too.
    let legacy = |types: &str| {
        raw_record(
            DACP,
            47,
            "NSEC",
            &format!("iTunes_Ctrl._dacp._tcp.local. {types}"),
            120,
        )
    };
    ingest(&mut app, &legacy("AAAA"));
    assert!(!rows_of(&app, DACP).contains(&28));
    ingest(&mut app, &legacy("TXT SRV"));
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::7", 120),
    );
    assert!(rows_of(&app, DACP).contains(&28));
}

#[test]
fn same_packet_additional_is_never_filed_on_a_denying_service() {
    // _dacp is knulp's only service, so nothing else files AAAA.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(&mut app, &srv_on_knulp(DACP));
    let key = ("knulp.local".to_string(), 28);
    let undamped = Duration::from_secs(4);
    app.continuous.insert(
        key.clone(),
        ContinuousQuery {
            next_due: Instant::now() + undamped,
            interval: undamped,
            qname: "knulp.local".to_string(),
        },
    );
    // One zeroconf response: SRV, inverted NSEC and a unique AAAA.
    let mut aaaa = aaaa_knulp();
    aaaa.flush_bit = true;
    app.ingest_event(&packet(vec![
        srv_on_knulp(DACP),
        raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 120),
        aaaa,
    ]));
    assert!(!rows_of(&app, DACP).contains(&28));
    // Never filed, so its cache-flush bit didn't damp the stream.
    assert_eq!(app.continuous.get(&key).unwrap().interval, undamped);
}

#[test]
fn pending_instance_picks_up_a_legacy_denial_on_promotion() {
    let mut app = App::new().unwrap();
    // PTR seen, SRV not yet: the instance is pending.
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(
        &mut app,
        &raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 120),
    );
    // AAAA arrives before the SRV (pending address), then the SRV.
    ingest(&mut app, &aaaa_knulp());
    ingest(&mut app, &a_knulp());
    ingest(&mut app, &srv_on_knulp(DACP));
    app.flush_pending_addrs();
    assert!(rows_of(&app, DACP).contains(&1));
    assert!(!rows_of(&app, DACP).contains(&28));
}

#[test]
fn denials_from_several_responders_collapse() {
    let mut app = knulp_app();
    for source in [
        "192.168.178.27:5353",
        "[fd00::d250:99ff:fe3b:8ce1]:5353",
        "172.17.0.1:5353",
    ] {
        let mut nsec = raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 120);
        nsec.source = source.parse().unwrap();
        ingest(&mut app, &nsec);
    }
    let dump = app.state_dump();
    let dacp = dump
        .services
        .iter()
        .find(|s| s.instance == "iTunes_Ctrl")
        .unwrap();
    assert_eq!(dacp.address_denials.len(), 1);
}

#[test]
fn rfc_denial_is_host_scoped_in_query_interest() {
    let mut app = knulp_app();
    // Both services deny AAAA for knulp via the RFC form.
    app.ingest_event(&packet(vec![
        srv_on_knulp(DACP),
        srv_on_knulp(SMB),
        raw_record("knulp.local.", 47, "NSEC", "knulp.local. A", 120),
    ]));
    let desired = app.desired_continuous();
    assert!(!desired.contains_key(&("knulp.local".to_string(), 28)));
    assert!(desired.contains_key(&("knulp.local".to_string(), 1)));
}
