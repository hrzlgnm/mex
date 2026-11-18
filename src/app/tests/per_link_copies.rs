// --- #264: one source heard on two links keeps a copy per link ---

use super::*;

#[test]
fn one_source_on_two_links_keeps_a_row_per_link() {
    let app = two_link_service();
    let rows = rows_with(&app, "192.168.1.10");
    assert_eq!(rows.len(), 2, "{rows:#?}");
    assert!(rows.iter().any(|r| r.contains("@eth0")), "{rows:#?}");
    assert!(rows.iter().any(|r| r.contains("@wlan0")), "{rows:#?}");
    // The dump lists both too.
    let dump = app.state_dump();
    let ifaces: Vec<&str> = dump.services[0]
        .answers
        .iter()
        .filter(|r| r.rtype == 1)
        .map(|r| r.iface.as_str())
        .collect();
    assert_eq!(ifaces.len(), 2, "{ifaces:?}");
}

#[test]
fn reannouncement_refreshes_only_its_link() {
    let mut app = two_link_service();
    for rec in &mut app.services[0].answers {
        if rec.rtype == 1 {
            rec.received_at = Instant::now()
                .checked_sub(Duration::from_secs(60))
                .unwrap_or_else(Instant::now);
        }
    }
    ingest(
        &mut app,
        &a_on("test.local.", "192.168.1.10", "eth0", 2, 120),
    );
    let rows = rows_with(&app, "192.168.1.10");
    let eth0 = rows.iter().find(|r| r.contains("@eth0")).unwrap();
    let wlan0 = rows.iter().find(|r| r.contains("@wlan0")).unwrap();
    assert!(eth0.contains("2m00s"), "refreshed: {eth0}");
    assert!(wlan0.contains("1m00s"), "untouched: {wlan0}");
}

#[test]
fn goodbye_on_one_link_withdraws_only_that_row() {
    let mut app = two_link_service();
    ingest(
        &mut app,
        &a_on("test.local.", "192.168.1.10", "wlan0", 3, 0),
    );
    let rows = rows_with(&app, "192.168.1.10");
    assert_eq!(rows.len(), 2, "{rows:#?}");
    let wlan0 = rows.iter().find(|r| r.contains("@wlan0")).unwrap();
    let eth0 = rows.iter().find(|r| r.contains("@eth0")).unwrap();
    assert!(wlan0.contains(" bye "), "{wlan0}");
    assert!(eth0.contains("2m00s"), "{eth0}");
}

#[test]
fn pending_address_keeps_its_links_until_claimed() {
    let mut app = App::new().unwrap();
    // Addresses first, on two links, before any service points there.
    ingest(
        &mut app,
        &a_on("test.local.", "192.168.1.10", "eth0", 2, 120),
    );
    ingest(
        &mut app,
        &a_on("test.local.", "192.168.1.10", "wlan0", 3, 120),
    );
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    app.flush_pending_addrs();
    app.evict_expired();
    select_instance(&mut app, "Test");
    assert_eq!(rows_with(&app, "192.168.1.10").len(), 2);
}

#[test]
fn withheld_address_survives_a_goodbye_on_the_other_link() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &raw_record("_dacp._tcp.local.", 12, "PTR", DACP, 4500),
    );
    ingest(&mut app, &srv_on_knulp(DACP));
    ingest(&mut app, &legacy_aaaa_denial());
    ingest(&mut app, &on_link(aaaa_knulp(), "eth0", 2));
    ingest(&mut app, &on_link(aaaa_knulp(), "wlan0", 3));
    assert!(!rows_of(&app, DACP).contains(&28), "denied on the service");
    let mut bye = on_link(aaaa_knulp(), "eth0", 2);
    bye.ttl = 0;
    ingest(&mut app, &bye);
    assert!(
        app.host_addresses("knulp.local")
            .iter()
            .any(|a| a == "fd00::1"),
        "still announced on wlan0"
    );
}

#[test]
fn conflict_on_a_second_link_is_not_hidden_by_an_overwrite() {
    let mut app = fritz_mesh();
    // The box announces the same address on both links, wlan0 first;
    // the repeater disagrees on wlan0 only.
    let mut wlan = aaaa("fritz.box.", BOX_ULA, BOX_V4);
    wlan.iface = "wlan0".into();
    wlan.ifindex = 3;
    let mut eth = wlan.clone();
    eth.iface = "eth0".into();
    eth.ifindex = 2;
    let mut rep = aaaa("fritz.box.", REP_ULA, REPEATER);
    rep.iface = "wlan0".into();
    rep.ifindex = 3;
    ingest(&mut app, &wlan);
    ingest(&mut app, &rep);
    ingest(&mut app, &eth);
    let found = conflicts(&app);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(
        found[0].message.contains("on wlan0"),
        "{}",
        found[0].message
    );
}

fn a_on(host: &str, addr: &str, iface: &str, ifindex: u32, ttl: u32) -> browse::RawRecord {
    on_link(raw_record(host, 1, "A", addr, ttl), iface, ifindex)
}

fn two_link_service() -> App {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    ingest(
        &mut app,
        &a_on("test.local.", "192.168.1.10", "eth0", 2, 120),
    );
    ingest(
        &mut app,
        &a_on("test.local.", "192.168.1.10", "wlan0", 3, 120),
    );
    app.evict_expired();
    select_instance(&mut app, "Test");
    app
}
