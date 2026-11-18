// --- Review follow-ups (#255) ---

use super::*;

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
    assert!(!rows_of(&app, DACP).contains(&28));
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
    assert!(!rows_of(&app, DACP).contains(&28));
}

#[test]
fn expired_nsec_never_removes_live_rows() {
    let mut app = knulp_app();
    let mut stale = legacy_aaaa_denial();
    stale.ttl = 1;
    stale.received_at = Instant::now() - Duration::from_secs(5);
    app.ingest_event(&packet(vec![stale]));
    assert!(
        rows_of(&app, DACP).contains(&28),
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
    assert!(!rows_of(&app, DACP).contains(&28));
    // _smb appears on the same host without that denial.
    ingest(
        &mut app,
        &raw_record("_smb._tcp.local.", 12, "PTR", SMB, 4500),
    );
    ingest(&mut app, &srv_on_knulp(SMB));
    assert!(rows_of(&app, SMB).contains(&28));
    assert!(!rows_of(&app, DACP).contains(&28));
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
    assert!(rows_of(&app, DACP).contains(&47), "NSEC row carried over");
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
    assert!(rows_of(&app, DACP).contains(&47));
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
    assert!(rows_of(&app, DACP).contains(&47));
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
    assert!(rows_of(&app, SMB).contains(&28), "sibling backfilled");
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
    assert!(rows_of(&app, DACP).contains(&28));
}
