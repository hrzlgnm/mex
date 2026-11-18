// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #248 PR 2: the findings a target shows, read from its Answers
// pane (the Anomalies pane is gone) ---

use super::*;

#[test]
fn record_findings_sit_under_their_own_row_only() {
    let mut app = App::new().unwrap();
    // Quiet 4500s base so the PTR row's only finding is the
    // shared-flush error from the set bit below.
    let mut ptr = ptr_record(4500);
    ptr.flush_bit = true;
    ingest(&mut app, &ptr);
    ingest(&mut app, &srv_record(120));
    app.evict_expired();
    select_instance(&mut app, "Test");
    assert_eq!(row_kinds(&app, 12, PTR_RDATA), ["shared-flush"]);
    assert!(
        !row_kinds(&app, 33, SRV_RDATA).contains(&"shared-flush"),
        "the healthy SRV row doesn't inherit the PTR's finding"
    );
}

#[test]
fn record_findings_sit_under_every_announcing_source() {
    // One responder announcing a record over IPv6 and IPv4: each
    // source's row carries its own finding, not only the row of the
    // first source the analyzer saw.
    assert_enum_subtype_per_copy(&[
        ("[fe80::1234%2]:5353", "enp12s0", 2),
        ("192.168.178.104:5353", "enp12s0", 2),
    ]);
}

#[test]
fn record_findings_stay_per_link_for_one_address() {
    // One address heard on two links: two rows, two findings, each
    // under its own link's row.
    assert_enum_subtype_per_copy(&[
        ("192.168.178.104:5353", "eth0", 2),
        ("192.168.178.104:5353", "wlan0", 3),
    ]);
}

#[test]
fn info_ttl_base_mismatch_shows_inline() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    app.evict_expired();
    select_instance(&mut app, "Test");
    let base = app
        .anomalies()
        .into_iter()
        .find(|a| a.kind == anomalies::AnomalyKind::TtlMismatch)
        .expect("base mismatch analyzed");
    assert_eq!(base.severity, anomalies::Severity::Info);
    assert_eq!(row_kinds(&app, 12, PTR_RDATA), ["ttl-mismatch"]);
}

#[test]
fn spanning_ttl_unstable_sits_under_every_row() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    // Same name and type, different TTL bases: one spanning finding.
    ingest(
        &mut app,
        &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 1, "A", "192.168.1.11", 4500),
    );
    app.evict_expired();
    select_instance(&mut app, "Test");
    for rdata in ["192.168.1.10", "192.168.1.11"] {
        assert!(
            row_kinds(&app, 1, rdata).contains(&"ttl-unstable"),
            "A {rdata} must carry the spanning finding"
        );
    }
    let spanning: Vec<_> = shown(&app)
        .into_iter()
        .filter(|(a, _)| a.kind == anomalies::AnomalyKind::TtlUnstable)
        .collect();
    assert!(
        spanning
            .iter()
            .all(|(a, _)| a.rtype_str.as_deref() == Some("A")),
        "spanning finding keeps its type label"
    );
    // A collapsed host header keeps showing the sticky service.
    select_host_header(&mut app, "test.local");
    assert!(shown_kinds(&app).contains(&"ttl-unstable"));
}

#[test]
fn unqueried_target_shows_no_resolution_finding() {
    let mut app = App::new().unwrap();
    // An unqueried target does not establish a resolution failure.
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    app.evict_expired();
    select_instance(&mut app, "Test");
    select_host_header(&mut app, "test.local");
    assert!(
        !shown_kinds(&app).contains(&"unresolved-srv-target"),
        "no address queries were transmitted"
    );
}

#[test]
fn enum_type_format_sits_under_its_ptr_row() {
    let mut app = App::new().unwrap();
    // Malformed enumerated type: the finding carries the PTR row's
    // identity, so it sits under that row of the enumeration entry.
    ingest(
        &mut app,
        &raw_record(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "badtype.local.",
            4500,
        ),
    );
    app.evict_expired();
    let enum_pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Enum { .. }))
        .expect("enum row");
    app.view_state.selected_display = enum_pos;
    app.clamp_selection();
    assert!(row_kinds(&app, 12, "badtype.local.").contains(&"type-format"));
    // The collapsed enumeration header keeps showing it.
    select_host_header(&mut app, ENUM_HOST);
    assert!(shown_kinds(&app).contains(&"type-format"));
}

#[test]
fn gone_rows_lose_their_findings() {
    let mut app = App::new().unwrap();
    let mut ptr = ptr_record(4500);
    ptr.flush_bit = true;
    ingest(&mut app, &ptr);
    ingest(&mut app, &srv_record(120));
    app.evict_expired();
    select_instance(&mut app, "Test");
    assert_eq!(row_kinds(&app, 12, PTR_RDATA), ["shared-flush"]);
    // Expired: the row goes quiet instead of keeping its finding.
    expire_rtype(&mut app, 12, 5000);
    assert!(row_kinds(&app, 12, PTR_RDATA).is_empty());
    // Goodbye: same.
    let mut app = App::new().unwrap();
    let mut ptr = ptr_record(4500);
    ptr.flush_bit = true;
    ingest(&mut app, &ptr);
    ingest(&mut app, &srv_record(120));
    ingest(&mut app, &ptr_record(0));
    select_instance(&mut app, "Test");
    assert!(row_kinds(&app, 12, PTR_RDATA).is_empty());
}

#[test]
fn finding_row_under_its_record_drops_source_icon_and_severity_word() {
    let mut app = App::new().unwrap();
    // shared-flush is an error: the red level icon carries the
    // severity, so the line spells no severity word.
    let mut ptr = ptr_record(4500);
    ptr.flush_bit = true;
    ingest(&mut app, &ptr);
    ingest(&mut app, &srv_record(120));
    app.evict_expired();
    select_instance(&mut app, "Test");
    let buf = render_to_buffer(&app, 160, 40);
    let area = app.layout.answers_rect.get();
    let text = rect_text(&buf, area);
    let line = text
        .lines()
        .find(|l| l.contains("shared-flush"))
        .unwrap_or_else(|| panic!("finding row: {text}"));
    assert!(!line.contains("error "), "no severity word: {line}");
    assert!(
        !line.contains("192.168.1.2:5353"),
        "the parent row names the source: {line}"
    );
    assert!(
        !line.contains('\u{f057}'),
        "icon only on the parent: {line}"
    );
    assert!(
        line.contains("PTR _http._tcp.local."),
        "names its row: {line}"
    );
    // Text starts in the TTL column, right after TYPE.
    let header = text.lines().nth(1).unwrap();
    let col = |l: &str, needle: &str| l[..l.find(needle).unwrap()].chars().count();
    assert_eq!(
        col(line, "shared-flush"),
        col(header, "TTL"),
        "{header}\n{line}"
    );
    // The parent PTR row carries the red error mark.
    let y = area.y
        + text
            .lines()
            .position(|l| l.contains("Test._http._tcp.local.") && l.contains("PTR"))
            .unwrap() as u16;
    let icon_fg = (area.x..area.x + area.width)
        .filter_map(|x| buf.cell((x, y)))
        .find(|c| c.symbol() == "\u{f057}")
        .map(|c| c.fg);
    assert_eq!(icon_fg, Some(ratatui::style::Color::Red));
}

#[test]
fn shared_identity_findings_name_their_rdata() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    // Same name and type, distinct rdata: two findings that share
    // their row identity.
    ingest(
        &mut app,
        &raw_record("test.local.", 1, "A", "192.168.1.10", 5),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 1, "A", "192.168.1.11", 5),
    );
    app.evict_expired();
    select_instance(&mut app, "Test");
    assert_eq!(row_kinds(&app, 1, "192.168.1.10"), ["ttl-low"]);
    assert_eq!(row_kinds(&app, 1, "192.168.1.11"), ["ttl-low"]);
    let buf = render_to_buffer(&app, 200, 40);
    let text = rect_text(&buf, app.layout.answers_rect.get());
    for rdata in ["192.168.1.10", "192.168.1.11"] {
        assert!(
            text.contains(&format!("A test.local. = {rdata}")),
            "lines must disambiguate shared identities, got: {text}"
        );
    }
}

#[test]
fn findings_never_leak_between_rows() {
    let mut app = App::new().unwrap();
    let mut ptr = ptr_record(4500);
    ptr.flush_bit = true;
    ingest(&mut app, &ptr);
    ingest(&mut app, &srv_record(120));
    ingest(
        &mut app,
        &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 1, "A", "192.168.1.11", 4500),
    );
    app.evict_expired();
    select_instance(&mut app, "Test");
    assert!(row_kinds(&app, 12, PTR_RDATA).contains(&"shared-flush"));
    assert!(!row_kinds(&app, 33, SRV_RDATA).contains(&"shared-flush"));
    assert!(!row_kinds(&app, 33, SRV_RDATA).contains(&"ttl-unstable"));
    for rdata in ["192.168.1.10", "192.168.1.11"] {
        let kinds = row_kinds(&app, 1, rdata);
        assert!(kinds.contains(&"ttl-unstable"), "{rdata}: {kinds:?}");
        assert!(!kinds.contains(&"shared-flush"), "{rdata}: {kinds:?}");
    }
}

#[test]
fn gone_rows_name_goodbye_and_expiry_in_the_ttl_cell() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    ingest(&mut app, &txt_record("a=1"));
    app.evict_expired();
    select_instance(&mut app, "Test");
    // Withdraw the SRV with a goodbye, let the TXT's TTL elapse.
    for rec in &mut app.services[0].answers {
        match rec.rtype {
            33 => rec.ttl = 0,
            16 => {
                rec.received_at = Instant::now()
                    .checked_sub(Duration::from_secs(5000))
                    .unwrap_or_else(Instant::now)
            }
            _ => {}
        }
    }
    let lines = answers_text(&app);
    let row = |prefix: &str| {
        lines
            .iter()
            .find(|l| l.starts_with(prefix))
            .unwrap_or_else(|| panic!("{prefix} row: {lines:#?}"))
            .clone()
    };
    let srv = row("│SRV");
    let txt = row("│TXT");
    assert!(srv.contains(" bye "), "goodbye row: {srv}");
    assert!(!srv.contains(" exp "), "goodbye is not an expiry: {srv}");
    assert!(txt.contains(" exp "), "expired row: {txt}");
}

#[test]
fn metrics_overlay_keeps_the_summary_and_lists_no_findings() {
    let mut app = App::new().unwrap();
    assert_eq!(summary(&app), "none");
    let mut bad = ptr_record(4500);
    bad.flush_bit = true;
    ingest(&mut app, &bad);
    ingest(&mut app, &srv_record(120));
    let found = app.anomalies();
    let count = |sev| found.iter().filter(|a| a.severity == sev).count();
    assert_eq!(
        summary(&app),
        format!(
            "{} error · {} warning · {} info",
            count(anomalies::Severity::Error),
            count(anomalies::Severity::Warning),
            count(anomalies::Severity::Info)
        )
    );
    assert!(count(anomalies::Severity::Error) >= 1);
    // The summary is the section's only row: no per-finding rows.
    let rows = app.metrics_rows();
    let at = rows.iter().position(|(k, _)| k == "Anomalies").unwrap();
    let section: Vec<_> = rows[at + 1..]
        .iter()
        .take_while(|(_, v)| !v.is_empty())
        .collect();
    assert_eq!(section.len(), 1, "{section:?}");
    // Every finding still reaches the state dump.
    let dump = app.state_dump();
    assert_eq!(
        dump.anomalies.len(),
        anomalies::collapse_questions(&found).len()
    );
}

/// Park the left selection on a collapsed host header: the detail
/// panes keep showing the last selected (sticky) target.
fn select_host_header(app: &mut App, key: &str) {
    app.collapsed_hosts.insert(key.to_string());
    let pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Host { label } if label == key))
        .unwrap_or_else(|| panic!("host header for {key}"));
    app.view_state.selected_display = pos;
    app.clamp_selection();
    assert!(app.selected_service().is_none());
}

/// Age every answer of this type past its TTL, turning live rows
/// into expired ones.
fn expire_rtype(app: &mut App, rtype: u16, secs: u64) {
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == rtype {
                rec.received_at = Instant::now()
                    .checked_sub(Duration::from_secs(secs))
                    .unwrap_or_else(Instant::now);
            }
        }
    }
}

/// Kinds of every finding the Answers pane shows, in pane order.
fn shown_kinds(app: &App) -> Vec<&'static str> {
    shown(app).iter().map(|(a, _)| a.kind.as_str()).collect()
}

/// Kinds of the findings under the raw-answer row with this identity.
fn row_kinds(app: &App, rtype: u16, rdata: &str) -> Vec<&'static str> {
    let idx = app
        .display_detail()
        .expect("target displayed")
        .ordered_answers()
        .iter()
        .position(|r| r.rtype == rtype && r.rdata == rdata)
        .unwrap_or_else(|| panic!("row for {rdata}"));
    shown(app)
        .iter()
        .filter(|(_, record)| *record == Some(idx))
        .map(|(a, _)| a.kind.as_str())
        .collect()
}

const PTR_RDATA: &str = "Test._http._tcp.local.";

const SRV_RDATA: &str = "0 0 80 test.local.";

/// Ingest one enumeration subtype PTR per (source, iface, ifindex)
/// copy and assert each copy's Answers row carries exactly one
/// `enum-subtype` finding, and the analyzer counts one per row.
fn assert_enum_subtype_per_copy(copies: &[(&str, &str, u32)]) {
    let mut app = App::new().unwrap();
    for (source, iface, ifindex) in copies {
        let mut rec = raw_record(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_T35._sub._matterd._udp.local.",
            120,
        );
        rec.source = source.parse().unwrap();
        rec.iface = (*iface).to_string();
        rec.ifindex = *ifindex;
        ingest(&mut app, &rec);
    }
    app.view_state.selected_display = app
        .display_items()
        .iter()
        .position(|d| matches!(d, DisplayItem::Enum { .. }))
        .unwrap();
    let target = app.display_detail().unwrap();
    let found = app.anomalies();
    let is_subtype = |a: &anomalies::Anomaly| a.kind == anomalies::AnomalyKind::EnumSubtype;
    assert_eq!(
        found.iter().filter(|a| is_subtype(a)).count(),
        copies.len(),
        "one finding per copy, so badges match the rows"
    );
    let layout = app.answers_layout(&target, &found);
    let answers = target.ordered_answers();
    for (source, _, ifindex) in copies {
        let row = answers
            .iter()
            .position(|r| r.source.to_string() == *source && r.ifindex == *ifindex)
            .unwrap();
        let under_row = layout
            .iter()
            .filter(|l| {
                matches!(
                    l,
                    AnswerLine::Finding { anomaly, record: Some(i) }
                        if *i == row && is_subtype(anomaly)
                )
            })
            .count();
        assert_eq!(under_row, 1, "enum-subtype under {source} #{ifindex}");
    }
}
