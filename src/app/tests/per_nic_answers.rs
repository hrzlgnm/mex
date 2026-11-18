// --- #271: one host answering per NIC on one link ---

use super::*;

#[test]
fn host_answering_a_per_nic_is_not_a_conflict() {
    let mut app = local_host();
    ingest(&mut app, &addr(1, NIC1_V4, &v4_source(NIC1_V4)));
    ingest(&mut app, &addr(1, NIC2_V4, &v4_source(NIC2_V4)));
    let found = conflicts(&app);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn host_answering_aaaa_per_nic_over_both_families_is_not_a_conflict() {
    let mut app = local_host();
    for (v4_ip, ll) in [(NIC1_V4, NIC1_LL), (NIC2_V4, NIC2_LL)] {
        ingest(&mut app, &addr(1, v4_ip, &v4_source(v4_ip)));
        for source in [v4_source(v4_ip), v6_source(ll)] {
            ingest(&mut app, &addr(28, ll, &source));
        }
    }
    let found = conflicts(&app);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn aaaa_over_v4_only_is_the_host_when_the_v4_source_is_announced() {
    // No v6 source seen yet: the v4 source, an announced A of the
    // host, still marks the group as the host's own.
    let mut app = local_host();
    for (v4_ip, ll) in [(NIC1_V4, NIC1_LL), (NIC2_V4, NIC2_LL)] {
        ingest(&mut app, &addr(1, v4_ip, &v4_source(v4_ip)));
        ingest(&mut app, &addr(28, ll, &v4_source(v4_ip)));
    }
    let found = conflicts(&app);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn multi_homed_host_and_a_foreign_responder_are_two_responders() {
    let app = host_and_foreign_responder();
    let found = conflicts(&app);
    assert_eq!(found.len(), 1, "{found:?}");
    let c = &found[0];
    assert_eq!(c.severity, anomalies::Severity::Warning);
    assert!(
        c.message
            .starts_with("2 responders disagree on test.local A"),
        "{}",
        c.message
    );
    let mut groups: Vec<(Vec<String>, Vec<String>)> = c
        .responders
        .iter()
        .map(|r| {
            let mut s = r.sources.clone();
            s.sort();
            (s, r.addresses.clone())
        })
        .collect();
    groups.sort();
    let foreign = "192.168.42.9:5353@br0".to_string();
    let mut host_sources = vec![
        "192.168.42.158:5353@br0".to_string(),
        "192.168.43.158:5353@br0".to_string(),
    ];
    host_sources.sort();
    let mut want = vec![
        (vec![foreign], vec!["192.168.42.7".to_string()]),
        (host_sources, vec![NIC1_V4.to_string(), NIC2_V4.to_string()]),
    ];
    want.sort();
    assert_eq!(groups, want);
}

#[test]
fn foreign_responder_gone_leaves_only_the_host() {
    let mut app = host_and_foreign_responder();
    assert_eq!(conflicts(&app).len(), 1);
    ingest(&mut app, &{
        let mut bye = addr(1, "192.168.42.7", &v4_source("192.168.42.9"));
        bye.ttl = 0;
        bye
    });
    let found = conflicts(&app);
    assert!(found.is_empty(), "goodbye ends it: {found:?}");
}

#[test]
fn proxy_agreeing_with_the_merged_host_is_not_a_conflict() {
    // A proxy announcing both NICs' addresses agrees with the host
    // as a whole, though with neither NIC alone.
    let mut app = local_host();
    ingest(&mut app, &addr(1, NIC1_V4, &v4_source(NIC1_V4)));
    ingest(&mut app, &addr(1, NIC2_V4, &v4_source(NIC2_V4)));
    for ip in [NIC1_V4, NIC2_V4] {
        ingest(&mut app, &addr(1, ip, &v4_source("192.168.42.9")));
    }
    let found = conflicts(&app);
    assert!(found.is_empty(), "{found:?}");
}

#[test]
fn foreign_responder_expiry_leaves_only_the_host() {
    let mut app = host_and_foreign_responder();
    assert_eq!(conflicts(&app).len(), 1);
    let foreign: SocketAddr = "192.168.42.9:5353".parse().unwrap();
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.source == foreign {
                rec.received_at = Instant::now()
                    .checked_sub(Duration::from_secs(500))
                    .unwrap_or_else(Instant::now);
            }
        }
    }
    let found = conflicts(&app);
    assert!(found.is_empty(), "expiry ends it: {found:?}");
}

#[test]
fn cursor_and_txt_expansion_stay_on_their_link() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    let txt = |iface: &str, ifindex| {
        on_link(
            raw_record("Test._http._tcp.local.", 16, "TXT", "a=1; b=2", 4500),
            iface,
            ifindex,
        )
    };
    ingest(&mut app, &txt("eth0", 2));
    ingest(&mut app, &txt("wlan0", 3));
    app.evict_expired();
    select_instance(&mut app, "Test");
    let wlan_idx = app
        .display_detail()
        .unwrap()
        .ordered_answers()
        .iter()
        .position(|r| r.rtype == 16 && r.ifindex == 3)
        .unwrap();
    app.view_state.detail_selected = wlan_idx;
    app.detail_anchor = app
        .display_detail()
        .and_then(|d| App::identity_at_detail(&d, wlan_idx));
    assert!(app.toggle_txt_expanded());
    // A refresh of the eth0 copy reorders nothing away from wlan0.
    ingest(&mut app, &txt("eth0", 2));
    app.clamp_selection();
    match app.selected_detail_entry() {
        Some(DetailEntry::Record(r)) => assert_eq!(r.ifindex, 3, "cursor stays on wlan0"),
        _ => panic!("cursor on a record"),
    }
    let target = app.display_detail().unwrap();
    let rows = target.ordered_answers();
    let expanded: Vec<u32> = rows
        .iter()
        .filter(|r| r.rtype == 16 && app.is_txt_expanded(r))
        .map(|r| r.ifindex)
        .collect();
    assert_eq!(expanded, vec![3], "expansion is per row");
}

#[test]
fn stale_pending_copy_does_not_shadow_a_live_withheld_one() {
    let mut app = fritz_mesh();
    ingest(&mut app, &aaaa("fritz.box.", BOX_ULA, BOX_V4));
    // The repeater's disagreeing address, cached twice under the same
    // identity: a stale pending copy and a live withheld one.
    let live = aaaa("fritz.box.", REP_ULA, REPEATER);
    let mut stale = live.clone();
    stale.received_at = Instant::now()
        .checked_sub(Duration::from_secs(500))
        .unwrap_or_else(Instant::now);
    app.pending_addrs
        .entry("fritz.box".to_string())
        .or_default()
        .push(stale);
    app.address_denials.withhold(&live);
    assert_eq!(conflicts(&app).len(), 1, "the live withheld copy counts");
}

#[test]
fn goodbye_on_one_link_keeps_a_service_announced_on_another_active() {
    let mut app = App::new().unwrap();
    let ptr = |ttl| on_link(ptr_record(ttl), "eth0", 2);
    let ptr_wlan = |ttl| on_link(ptr_record(ttl), "wlan0", 3);
    ingest(&mut app, &ptr(4500));
    ingest(&mut app, &ptr_wlan(4500));
    ingest(&mut app, &srv_record(120));
    app.evict_expired();
    select_instance(&mut app, "Test");
    ingest(&mut app, &ptr(0));
    assert!(app.services[0].is_active, "still announced on wlan0");
    let rows = rows_with(&app, "Test._http._tcp.local.");
    let eth0 = rows.iter().find(|r| r.contains("@eth0")).unwrap();
    let wlan0 = rows.iter().find(|r| r.contains("@wlan0")).unwrap();
    assert!(eth0.contains(" bye "), "{eth0}");
    assert!(!wlan0.contains(" bye "), "{wlan0}");
    // The last live copy saying goodbye still withdraws the service.
    ingest(&mut app, &ptr_wlan(0));
    assert!(!app.services[0].is_active, "withdrawn everywhere");
}

#[test]
fn question_finding_row_drops_the_querier_and_starts_in_last() {
    let mut app = test_service_app();
    app.evict_expired();
    select_instance(&mut app, "Test");
    let querier: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    app.ingest_event(&query_event(
        "Test._http._tcp.local.",
        16,
        "TXT",
        false,
        Vec::new(),
        querier,
    ));
    // No analyzer kind files on a Questions row today; inject one.
    let mut found = app.anomalies();
    found.push(anomalies::Anomaly {
        kind: anomalies::AnomalyKind::UnsupportedQuestion,
        severity: anomalies::Severity::Info,
        service: "Test._http._tcp.local".to_string(),
        record_name: Some("Test._http._tcp.local.".to_string()),
        rtype: Some(16),
        rtype_str: Some("TXT".to_string()),
        rdata: None,
        source: Some(querier.to_string()),
        message: "injected question finding".to_string(),
        rfc: "RFC 6762 §5",
        requirement: "",
        response: None,
        responders: Vec::new(),
    });
    let backend = ratatui::backend::TestBackend::new(160, 40);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| crate::ui::draw_with_findings(f, &app, &found))
        .unwrap();
    let text = rect_text(term.backend().buffer(), app.layout.questions_rect.get());
    let lines: Vec<&str> = text.lines().collect();
    let row = lines
        .iter()
        .find(|l| l.contains("injected question finding"))
        .unwrap_or_else(|| panic!("{text}"));
    assert!(!row.contains("192.168.1.77"), "{row}");
    let col = |l: &str, needle: &str| l[..l.find(needle).unwrap()].chars().count();
    assert_eq!(
        col(row, "unsupported-question"),
        col(lines[1], "LAST"),
        "{text}"
    );
}

/// NIC 1 / NIC 2 of one multi-homed host on one bridge: each answers
/// from its own addresses with only those addresses (RFC 6762 §6.2).
const NIC1_V4: &str = "192.168.42.158";

const NIC2_V4: &str = "192.168.43.158";

const NIC1_LL: &str = "fe80::219:7cff:fe01:5801";

const NIC2_LL: &str = "fe80::219:7cff:fe01:5802";

/// A `.local` service whose SRV target `test.local` has its address
/// records judged by `conflicting-answers`.
fn local_host() -> App {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    app
}

fn v4_source(ip: &str) -> String {
    format!("{ip}:5353")
}

fn v6_source(ip: &str) -> String {
    format!("[{ip}%8]:5353")
}

/// The multi-homed host plus a foreign responder (a proxy answering
/// from an address the host does not announce) with its own claim.
fn host_and_foreign_responder() -> App {
    let mut app = local_host();
    ingest(&mut app, &addr(1, NIC1_V4, &v4_source(NIC1_V4)));
    ingest(&mut app, &addr(1, NIC2_V4, &v4_source(NIC2_V4)));
    ingest(
        &mut app,
        &addr(1, "192.168.42.7", &v4_source("192.168.42.9")),
    );
    app
}
