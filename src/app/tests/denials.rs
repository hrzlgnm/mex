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
    assert!(live_rows(&app, DACP).contains(&1), "A stays");
    assert!(
        !live_rows(&app, DACP).contains(&28),
        "earlier AAAA taken back"
    );
    assert!(live_rows(&app, SMB).contains(&28), "sibling keeps its AAAA");
    // A later AAAA is not filed on _dacp either.
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::2", 120),
    );
    assert!(!live_rows(&app, DACP).contains(&28));
    assert!(live_rows(&app, SMB).contains(&28));
    // The NSEC row itself stays visible, and the host still lists v6.
    assert!(live_rows(&app, DACP).contains(&47));
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
    assert!(live_rows(&app, DACP).contains(&28));
    assert!(live_rows(&app, SMB).contains(&28));
}

#[test]
fn legacy_instance_nsec_denies_listed_types_and_is_flagged() {
    let mut app = knulp_app();
    ingest(
        &mut app,
        &raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 120),
    );
    assert!(!live_rows(&app, DACP).contains(&28));
    assert!(live_rows(&app, SMB).contains(&28));
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
    assert!(live_rows(&app, DACP).contains(&28));
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
    assert!(!live_rows(&app, DACP).contains(&28));
    app.ingest_event(&packet(vec![legacy(0)]));
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::3", 120),
    );
    assert!(
        live_rows(&app, DACP).contains(&28),
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
    assert!(live_rows(&app, DACP).contains(&28));
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
    assert!(!live_rows(&app, DACP).contains(&28));
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
    assert!(live_rows(&app, DACP).contains(&28));
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
    assert!(!live_rows(&app, DACP).contains(&28));
    // The host gained IPv6: the new bitmap lists AAAA, lifting it.
    app.ingest_event(&packet(vec![srv_on_knulp(DACP), nsec("A AAAA")]));
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::6", 120),
    );
    assert!(live_rows(&app, DACP).contains(&28));
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
    assert!(!live_rows(&app, DACP).contains(&28));
    ingest(&mut app, &legacy("TXT SRV"));
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::7", 120),
    );
    assert!(live_rows(&app, DACP).contains(&28));
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
    app.scheduler.continuous_mut().insert(
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
    assert!(!live_rows(&app, DACP).contains(&28));
    // Never filed, so its cache-flush bit didn't damp the stream.
    assert_eq!(
        app.scheduler.continuous().get(&key).unwrap().interval,
        undamped
    );
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
    assert!(live_rows(&app, DACP).contains(&1));
    assert!(!live_rows(&app, DACP).contains(&28));
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

// Follow-ups from the #245 review (#255).

#[test]
fn withheld_address_of_an_alternate_target_stays_in_the_header() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(&mut app, &srv_on_knulp(DACP));
    let mut alt = raw_record(DACP, 33, "SRV", "0 0 3689 other.local.", 120);
    alt.flush_bit = true;
    alt.source = "192.168.178.9:5353".parse().unwrap();
    ingest(&mut app, &alt);
    ingest(&mut app, &legacy_aaaa_denial());
    let selected = app.services[0]
        .hostname
        .trim_end_matches('.')
        .to_lowercase();
    let other = if selected == "knulp.local" {
        "other.local."
    } else {
        "knulp.local."
    };
    ingest(&mut app, &raw_record(other, 28, "AAAA", "fd00::a", 120));
    assert!(!live_rows(&app, DACP).contains(&28));
    assert!(
        app.host_addresses(&selected).iter().any(|a| a == "fd00::a"),
        "withheld AAAA of the alternate target {other} still listed"
    );
}

#[test]
fn legacy_denial_for_an_instance_first_seen_in_the_same_packet() {
    let mut app = App::new().unwrap();
    // PTR and instance NSEC together, no SRV yet.
    app.ingest_event(&packet(vec![
        raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
        legacy_aaaa_denial(),
    ]));
    ingest(&mut app, &aaaa_knulp());
    ingest(&mut app, &srv_on_knulp(DACP));
    app.flush_pending_addrs();
    assert!(!live_rows(&app, DACP).contains(&28));
}

#[test]
fn expired_nsec_never_removes_live_rows() {
    let mut app = knulp_app();
    let mut stale = legacy_aaaa_denial();
    stale.ttl = 1;
    stale.received_at = Instant::now() - Duration::from_secs(5);
    app.ingest_event(&packet(vec![stale]));
    assert!(
        live_rows(&app, DACP).contains(&28),
        "no evict needed: never removed"
    );
}

#[test]
fn address_goodbye_after_a_lift_clears_the_withheld_copy() {
    let mut app = knulp_app();
    ingest(&mut app, &legacy_aaaa_denial());
    // The denial lifts, then the address is withdrawn.
    let mut lift = legacy_aaaa_denial();
    lift.ttl = 0;
    app.ingest_event(&packet(vec![lift]));
    let mut bye = aaaa_knulp();
    bye.ttl = 0;
    app.ingest_event(&packet(vec![bye]));
    assert!(
        !app.host_addresses("knulp.local")
            .iter()
            .any(|a| a == "fd00::1"),
        "withdrawn address no longer listed"
    );
}

#[test]
fn new_sibling_backfills_an_address_only_held_as_withheld() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(&mut app, &srv_on_knulp(DACP));
    ingest(&mut app, &legacy_aaaa_denial());
    ingest(&mut app, &aaaa_knulp());
    assert!(!live_rows(&app, DACP).contains(&28));
    // _smb appears on the same host without that denial.
    ingest(
        &mut app,
        &raw_record("_smb._tcp.local.", 12, "PTR", SMB, 4500),
    );
    ingest(&mut app, &srv_on_knulp(SMB));
    assert!(live_rows(&app, SMB).contains(&28));
    assert!(!live_rows(&app, DACP).contains(&28));
}

#[test]
fn nsec_rows_survive_promotion_and_srv_order() {
    // Legacy NSEC for a pending instance: row and finding kept.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(&mut app, &legacy_aaaa_denial());
    ingest(&mut app, &srv_on_knulp(DACP));
    assert!(live_rows(&app, DACP).contains(&47), "NSEC row carried over");
    assert!(app
        .anomalies()
        .iter()
        .any(|a| a.kind == anomalies::AnomalyKind::NsecInvertedBitmap));
    // RFC NSEC placed before the SRV that creates the service.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    app.ingest_event(&packet(vec![
        raw_record("knulp.local.", 47, "NSEC", "knulp.local. A", 120),
        srv_on_knulp(DACP),
        a_knulp(),
    ]));
    assert!(live_rows(&app, DACP).contains(&47));
}

#[test]
fn sibling_address_of_a_denied_family_does_not_resolve() {
    // _smb holds knulp's AAAA; _dacp denies AAAA and has no A, and
    // its A lookup went unanswered: _dacp is unresolved.
    let mut app = knulp_app();
    ingest(&mut app, &legacy_aaaa_denial());
    mark_address_queries(&mut app, "knulp.local", Duration::from_secs(2));
    let found: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| {
            a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget
                && a.service == "iTunes_Ctrl._dacp._tcp.local"
        })
        .collect();
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].message.contains("AAAA: denied by NSEC"),
        "{}",
        found[0].message
    );
}

#[test]
fn hostname_nsec_row_kept_for_an_alternate_srv_target() {
    // SRV host-a, NSEC host-a, SRV host-b: host-b becomes selected,
    // the NSEC row still belongs to the service via host-a.
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    let mut srv_b = raw_record(DACP, 33, "SRV", "0 0 3689 other.local.", 120);
    srv_b.flush_bit = true;
    srv_b.source = "192.168.178.9:5353".parse().unwrap();
    app.ingest_event(&packet(vec![
        srv_on_knulp(DACP),
        raw_record("knulp.local.", 47, "NSEC", "knulp.local. A", 120),
        srv_b,
    ]));
    assert!(live_rows(&app, DACP).contains(&47));
}

#[test]
fn backfill_keeps_the_hosts_withheld_copy() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(&mut app, &srv_on_knulp(DACP));
    ingest(&mut app, &legacy_aaaa_denial());
    ingest(&mut app, &aaaa_knulp());
    ingest(
        &mut app,
        &raw_record("_smb._tcp.local.", 12, "PTR", SMB, 4500),
    );
    ingest(&mut app, &srv_on_knulp(SMB));
    assert!(live_rows(&app, SMB).contains(&28), "sibling backfilled");
    // The sibling goes away: the host still lists its live AAAA.
    app.services.retain(|s| s.instance != "KNULP");
    assert!(app
        .host_addresses("knulp.local")
        .iter()
        .any(|a| a == "fd00::1"));
}

#[test]
fn evicted_owner_takes_its_denial_in_the_same_pass() {
    let mut app = knulp_app();
    ingest(&mut app, &legacy_aaaa_denial());
    // _dacp is withdrawn and past its grace period.
    for s in app
        .services
        .iter_mut()
        .filter(|s| s.instance == "iTunes_Ctrl")
    {
        s.is_active = false;
        s.last_seen = Instant::now() - Duration::from_secs(600);
    }
    app.evict_expired();
    assert!(app.services.iter().all(|s| s.instance != "iTunes_Ctrl"));
    // It returns before any later pass: no stale denial.
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(&mut app, &srv_on_knulp(DACP));
    ingest(
        &mut app,
        &raw_record("knulp.local.", 28, "AAAA", "fd00::b", 120),
    );
    assert!(live_rows(&app, DACP).contains(&28));
}
