// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #247: conflicting address answers ---

use super::*;

#[test]
fn mesh_repeater_disagreeing_on_aaaa_is_one_info_finding() {
    let app = disagreeing_mesh();
    let found = conflicts(&app);
    assert_eq!(found.len(), 1, "AAAA only, no A finding: {found:?}");
    let c = &found[0];
    assert_eq!(c.service, "fritz.box", "owned by the host");
    assert_eq!(c.rtype, Some(28));
    assert_eq!(
        c.severity,
        anomalies::Severity::Info,
        "shared records, not .local"
    );
    assert_eq!(c.responders.len(), 2, "{:?}", c.responders);
    let mut box_sources = vec![BOX_V4.to_string(), BOX_LL.to_string()];
    box_sources.sort();
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
    let mut want = vec![
        (box_sources, {
            let mut a = vec![BOX_ULA.to_string(), BOX_GUA.to_string()];
            a.sort();
            a
        }),
        (vec![REPEATER.to_string()], {
            let mut a = vec![REP_ULA.to_string(), REP_GUA.to_string()];
            a.sort();
            a
        }),
    ];
    want.sort();
    assert_eq!(groups, want);
    // Device names (#246) annotate the groups in the message.
    assert!(
        c.message
            .starts_with("2 responders disagree on fritz.box AAAA"),
        "{}",
        c.message
    );
    assert!(c.message.contains("(FritzBoxRepeater)"), "{}", c.message);
    assert!(c.message.contains("(~fritz)"), "{}", c.message);
}

#[test]
fn one_device_on_several_sources_is_not_a_conflict() {
    let mut app = fritz_mesh();
    for source in [BOX_V4, BOX_LL] {
        for addr in [BOX_ULA, BOX_GUA] {
            ingest(&mut app, &aaaa("fritz.box.", addr, source));
        }
    }
    assert!(conflicts(&app).is_empty());
}

#[test]
fn extra_address_on_one_responder_is_a_conflict() {
    let mut app = fritz_mesh();
    ingest(&mut app, &aaaa("fritz.box.", BOX_ULA, BOX_V4));
    ingest(&mut app, &aaaa("fritz.box.", BOX_ULA, REPEATER));
    assert!(conflicts(&app).is_empty(), "identical sets");
    ingest(&mut app, &aaaa("fritz.box.", "fd00::dead", REPEATER));
    assert_eq!(conflicts(&app).len(), 1);
}

#[test]
fn local_hostname_or_flush_bit_makes_it_a_warning() {
    // A `.local` clash with shared records only.
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    ingest(
        &mut app,
        &from(
            raw_record("test.local.", 1, "A", "192.168.1.10", 120),
            "192.168.1.2:5353",
        ),
    );
    ingest(
        &mut app,
        &from(
            raw_record("test.local.", 1, "A", "192.168.1.11", 120),
            "192.168.1.3:5353",
        ),
    );
    let found = conflicts(&app);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].severity, anomalies::Severity::Warning);
    // Outside mDNS domains, a cache-flush bit claims uniqueness.
    let mut app = fritz_mesh();
    ingest(&mut app, &aaaa("fritz.box.", BOX_ULA, BOX_V4));
    let mut rep = aaaa("fritz.box.", REP_ULA, REPEATER);
    rep.flush_bit = true;
    ingest(&mut app, &rep);
    let found = conflicts(&app);
    assert_eq!(found.len(), 1);
    assert_eq!(found[0].severity, anomalies::Severity::Warning);
}

#[test]
fn responders_on_different_links_do_not_conflict() {
    let mut app = fritz_mesh();
    let mut a = aaaa("fritz.box.", BOX_ULA, BOX_V4);
    a.iface = "eth0".to_string();
    let mut b = aaaa("fritz.box.", REP_ULA, REPEATER);
    b.iface = "wlan0".to_string();
    ingest(&mut app, &a);
    ingest(&mut app, &b);
    assert!(conflicts(&app).is_empty());
}

#[test]
fn goodbye_or_expiry_of_the_repeater_ends_the_conflict() {
    let mut app = disagreeing_mesh();
    assert_eq!(conflicts(&app).len(), 1);
    for addr in [REP_ULA, REP_GUA] {
        ingest(
            &mut app,
            &from(raw_record("fritz.box.", 28, "AAAA", addr, 0), REPEATER),
        );
    }
    assert!(conflicts(&app).is_empty(), "goodbye ends it");
    let mut app = disagreeing_mesh();
    let repeater: SocketAddr = REPEATER.parse().unwrap();
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.source == repeater && rec.rtype == 28 {
                rec.received_at = Instant::now()
                    .checked_sub(Duration::from_secs(500))
                    .unwrap_or_else(Instant::now);
            }
        }
    }
    assert!(conflicts(&app).is_empty(), "expiry ends it");
}

#[test]
fn conflict_shows_in_every_sibling_host_block_and_badges_once() {
    let mut app = disagreeing_mesh();
    // A second service on the same host.
    ingest(
        &mut app,
        &from(
            raw_record(
                "_tr064._tcp.local.",
                12,
                "PTR",
                "Fritzel._tr064._tcp.local.",
                4500,
            ),
            BOX_V4,
        ),
    );
    let mut srv = raw_record(
        "Fritzel._tr064._tcp.local.",
        33,
        "SRV",
        "0 0 49000 fritz.box.",
        120,
    );
    srv.flush_bit = true;
    ingest(&mut app, &from(srv, BOX_V4));
    app.evict_expired();
    assert_eq!(conflicts(&app).len(), 1, "recorded once, for the host");
    let ids: Vec<usize> = app
        .services
        .iter()
        .enumerate()
        .filter(|(_, s)| s.instance == "Fritzel")
        .map(|(i, _)| i)
        .collect();
    assert_eq!(ids.len(), 2);
    for i in ids {
        let pos = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Instance { index } if *index == i))
            .unwrap();
        app.view_state.selected_display = pos;
        app.clamp_selection();
        let lines = answers_text(&app);
        let block = lines
            .iter()
            .position(|l| l.starts_with("│host fritz.box"))
            .unwrap_or_else(|| panic!("{lines:#?}"));
        assert!(
            block_has(&lines, block, "conflicting-answers"),
            "{lines:#?}"
        );
    }
    let counts = app.anomaly_counts();
    let host_findings = app
        .anomalies()
        .iter()
        .filter(|a| a.service == "fritz.box")
        .count();
    assert_eq!(counts.get("fritz.box"), Some(&host_findings));
    assert!(
        app.services.iter().all(|s| !app
            .anomalies()
            .iter()
            .any(|a| a.kind == anomalies::AnomalyKind::ConflictingAnswers
                && a.service == anomalies::service_id(&s.instance, &s.service_type))),
        "instances don't repeat the host's conflict"
    );
}

#[test]
fn dump_lists_responders_once_with_public_addresses_masked() {
    let app = disagreeing_mesh();
    let dump = app.state_dump();
    let found: Vec<_> = dump
        .anomalies
        .iter()
        .filter(|a| a.kind == "conflicting-answers")
        .collect();
    assert_eq!(found.len(), 1);
    let c = found[0];
    assert_eq!(c.responders.len(), 2);
    let all: Vec<&String> = c
        .responders
        .iter()
        .flat_map(|r| r.addresses.iter())
        .collect();
    assert!(
        all.iter().any(|a| a.as_str() == BOX_ULA),
        "ULA kept: {all:?}"
    );
    assert!(
        !all.iter().any(|a| a.as_str() == BOX_GUA),
        "public masked: {all:?}"
    );
    assert!(
        !c.message.contains(BOX_GUA),
        "message masked too: {}",
        c.message
    );
    assert!(c
        .responders
        .iter()
        .any(|r| r.name.as_deref() == Some("FritzBoxRepeater")));
    let json = serde_json::to_value(&dump).unwrap();
    let other = json["anomalies"]
        .as_array()
        .unwrap()
        .iter()
        .find(|a| a["kind"] != "conflicting-answers")
        .expect("another finding");
    assert!(other.get("responders").is_none(), "omitted for other kinds");
}

#[test]
fn conflict_leaves_address_rows_unchanged() {
    let app = disagreeing_mesh();
    let svc = app
        .services
        .iter()
        .find(|s| s.instance == "Fritzel")
        .unwrap();
    let aaaa_rows = svc
        .ordered_answers()
        .iter()
        .filter(|r| r.rtype == 28)
        .count();
    // Box: 2 addresses x 2 sources, repeater: 2.
    assert_eq!(aaaa_rows, 6);
}

#[test]
fn unsourced_finding_text_spans_the_source_column() {
    let mut app = disagreeing_mesh();
    select_instance(&mut app, "Fritzel");
    let lines = answers_text(&app);
    let row = lines
        .iter()
        .find(|l| l.contains("conflicting-answers"))
        .unwrap_or_else(|| panic!("{lines:#?}"));
    // The text starts where SOURCE starts, not in the RDATA column.
    let header = &lines[1];
    let col = |line: &str, needle: &str| line[..line.find(needle).unwrap()].chars().count();
    let src_col = col(header, "SOURCE");
    let text_col = col(row, "conflicting-answers");
    assert_eq!(text_col, src_col, "{header}\n{row}");
    assert!(row.contains("2 responders disagree"), "{row}");
}

#[test]
fn dump_masks_prefix_overlapping_addresses_whole() {
    // `2003::1` is a prefix of `2003::1:5`: masking must not touch
    // the longer address through the shorter one.
    let mut app = fritz_mesh();
    ingest(&mut app, &aaaa("fritz.box.", "2003::1", BOX_V4));
    ingest(&mut app, &aaaa("fritz.box.", "2003::1:5", REPEATER));
    let dump = app.state_dump();
    let c = dump
        .anomalies
        .iter()
        .find(|a| a.kind == "conflicting-answers")
        .expect("conflict");
    let short = dump::redact_ip_literal("2003::1");
    let long = dump::redact_ip_literal("2003::1:5");
    assert_ne!(short, long);
    assert!(c.message.contains(&short), "{}", c.message);
    assert!(c.message.contains(&long), "{}", c.message);
    assert!(
        !c.message.contains("2003::"),
        "nothing left unmasked: {}",
        c.message
    );
}

#[test]
fn unnamed_links_stay_apart_by_index() {
    let mut app = fritz_mesh();
    let mut a = aaaa("fritz.box.", BOX_ULA, BOX_V4);
    a.ifindex = 7;
    let mut b = aaaa("fritz.box.", REP_ULA, REPEATER);
    b.ifindex = 8;
    ingest(&mut app, &a);
    ingest(&mut app, &b);
    assert!(conflicts(&app).is_empty(), "no names, different links");
    // Same unnamed link: a conflict, named by its index.
    let mut c = aaaa("fritz.box.", REP_GUA, REPEATER);
    c.ifindex = 7;
    ingest(&mut app, &c);
    let found = conflicts(&app);
    assert_eq!(found.len(), 1, "{found:?}");
    assert!(found[0].message.contains(" on #7"), "{}", found[0].message);
}

#[test]
fn stale_copy_on_an_earlier_service_does_not_hide_a_live_one() {
    let mut app = disagreeing_mesh();
    // A second service on the host, filed after Fritzel.
    ingest(
        &mut app,
        &from(
            raw_record(
                "_tr064._tcp.local.",
                12,
                "PTR",
                "Fritzel._tr064._tcp.local.",
                4500,
            ),
            BOX_V4,
        ),
    );
    let mut srv = raw_record(
        "Fritzel._tr064._tcp.local.",
        33,
        "SRV",
        "0 0 49000 fritz.box.",
        120,
    );
    srv.flush_bit = true;
    ingest(&mut app, &from(srv, BOX_V4));
    app.evict_expired();
    let repeater: SocketAddr = REPEATER.parse().unwrap();
    let first = app
        .services
        .iter()
        .position(|s| {
            s.answers
                .iter()
                .any(|r| r.rtype == 28 && r.source == repeater)
        })
        .unwrap();
    let later = app
        .services
        .iter()
        .rposition(|s| {
            s.answers
                .iter()
                .any(|r| r.rtype == 28 && r.source == repeater)
        })
        .unwrap();
    assert_ne!(first, later, "both services hold a copy");
    // The earlier service's copies go stale; the later one's stay live.
    for rec in &mut app.services[first].answers {
        if rec.rtype == 28 && rec.source == repeater {
            rec.received_at = Instant::now()
                .checked_sub(Duration::from_secs(500))
                .unwrap_or_else(Instant::now);
        }
    }
    assert_eq!(conflicts(&app).len(), 1, "the live copy still counts");
}

const BOX_GUA: &str = "2003:a:b:c:7eff:4dff:fe15:7f88";

const REP_GUA: &str = "2003:a:b:c:ca0e:14ff:feff:416";

/// The observed mesh: the box announces its AAAA pair and its A from
/// both of its sources, the repeater its own AAAA pair for the same
/// name (and no A).
fn disagreeing_mesh() -> App {
    let mut app = fritz_mesh();
    for source in [BOX_V4, BOX_LL] {
        for addr in [BOX_ULA, BOX_GUA] {
            ingest(&mut app, &aaaa("fritz.box.", addr, source));
        }
        ingest(
            &mut app,
            &from(
                raw_record("fritz.box.", 1, "A", "192.168.178.1", 120),
                source,
            ),
        );
    }
    for addr in [REP_ULA, REP_GUA] {
        ingest(&mut app, &aaaa("fritz.box.", addr, REPEATER));
    }
    app
}
