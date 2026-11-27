// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #248: findings next to their owner ---

use super::*;

#[test]
fn record_finding_sits_under_its_row_marked_once() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let no_flush = finding(&app, anomalies::AnomalyKind::NoFlush);
    let lines = answers_text(&app);
    let txt = lines
        .iter()
        .position(|l| l.contains("▸ TXT"))
        .expect("TXT row");
    let marker = format!("TXT {}", icon(no_flush.severity));
    assert!(
        lines[txt].contains(&marker),
        "type cell marked: {}",
        lines[txt]
    );
    assert!(
        lines[txt + 1].contains("no-flush"),
        "finding child row follows its record: {lines:#?}"
    );
    // The icon shows once, on the parent's marked cell (#266).
    assert!(
        !lines[txt + 1].contains(icon(no_flush.severity)),
        "{}",
        lines[txt + 1]
    );
    // No `!` suffix anywhere any more.
    assert!(!lines.iter().any(|l| l.contains("TXT!")));
}

#[test]
fn ttl_finding_marks_the_ttl_cell_and_info_shows_inline() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let mismatch = finding(&app, anomalies::AnomalyKind::TtlMismatch);
    assert_eq!(mismatch.severity, anomalies::Severity::Info);
    let info = icon(anomalies::Severity::Info);
    let lines = answers_text(&app);
    let ptr = lines
        .iter()
        .position(|l| l.contains("PTR ") && l.contains("Test._http._tcp.local."))
        .expect("PTR row");
    assert!(
        lines[ptr].contains(&format!("s {info}")),
        "TTL cell carries the info icon: {}",
        lines[ptr]
    );
    assert!(
        !lines[ptr].contains(&format!("PTR {info}")),
        "type cell stays plain for a TTL kind: {}",
        lines[ptr]
    );
    assert!(lines[ptr + 1].contains("ttl-mismatch"));
}

#[test]
fn worst_finding_picks_the_row_marker() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let found = app.anomalies();
    let target = app.display_detail().unwrap();
    let txt = target
        .ordered_answers()
        .into_iter()
        .position(|r| r.rtype == 16)
        .unwrap();
    // Add an info finding on the same TXT row: the warning still wins.
    let mut extra = found
        .iter()
        .find(|a| a.kind == anomalies::AnomalyKind::NoFlush)
        .unwrap()
        .clone();
    extra.severity = anomalies::Severity::Info;
    extra.kind = anomalies::AnomalyKind::TypeFormat;
    let mut with_extra = found.clone();
    with_extra.push(extra);
    let layout = app.answers_layout(&target, &with_extra);
    let row: Vec<_> = layout
        .iter()
        .filter_map(|l| match l {
            AnswerLine::Finding {
                anomaly,
                record: Some(r),
            } if *r == txt => Some(anomaly.severity),
            _ => None,
        })
        .collect();
    assert_eq!(row.len(), 2, "every finding gets its own child row");
    let buf = {
        let backend = ratatui::backend::TestBackend::new(160, 40);
        let mut term = ratatui::Terminal::new(backend).unwrap();
        term.draw(|f| crate::ui::draw_with_findings(f, &app, &with_extra))
            .unwrap();
        term.backend().buffer().clone()
    };
    let text = rect_text(&buf, app.layout.answers_rect.get());
    let warn = icon(anomalies::Severity::Warning);
    assert!(
        text.lines().any(|l| l.contains(&format!("TXT {warn}"))),
        "worst (warning) icon on the row: {text}"
    );
}

#[test]
fn enter_folds_txt_pairs_and_findings_stay_before_them() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let key = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(&key(KeyCode::Tab));
    app.handle_key(&key(KeyCode::Enter));
    let lines = answers_text(&app);
    let txt = lines.iter().position(|l| l.contains("▾ TXT")).unwrap();
    assert!(lines[txt + 1].contains("no-flush"), "{lines:#?}");
    assert!(lines[txt + 2].contains("├─ a=1"), "{lines:#?}");
    assert!(lines[txt + 3].contains("└─ b=2"), "{lines:#?}");
    app.handle_key(&key(KeyCode::Enter));
    let lines = answers_text(&app);
    let txt = lines.iter().position(|l| l.contains("▸ TXT")).unwrap();
    assert!(
        lines[txt + 1].contains("no-flush"),
        "finding survives the fold"
    );
    assert!(!lines.iter().any(|l| l.contains("├─ a=1")));
}

#[test]
fn cursor_skips_finding_rows() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let key = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(&key(KeyCode::Tab));
    let _ = answers_text(&app);
    // TXT -> SRV, then PTR (with its ttl-mismatch child) -> SRV: one
    // step each way.
    app.handle_key(&key(KeyCode::Char('k')));
    match app.selected_detail_entry() {
        Some(DetailEntry::Record(r)) => assert_eq!(r.rtype, 33),
        _ => panic!("cursor on a record"),
    }
    app.handle_key(&key(KeyCode::Char('k')));
    match app.selected_detail_entry() {
        Some(DetailEntry::Record(r)) => assert_eq!(r.rtype, 12),
        _ => panic!("cursor on a record"),
    }
    app.handle_key(&key(KeyCode::Char('j')));
    match app.selected_detail_entry() {
        Some(DetailEntry::Record(r)) => assert_eq!(r.rtype, 33),
        _ => panic!("cursor on a record"),
    }
    // The highlighted (REVERSED) row is the SRV row, not a child.
    let buf = render_to_buffer(&app, 160, 40);
    let area = app.layout.answers_rect.get();
    let reversed: String = (area.y..area.y + area.height)
        .filter(|&y| {
            buf.cell((area.x + 2, y))
                .is_some_and(|c| c.modifier.contains(ratatui::style::Modifier::REVERSED))
        })
        .map(|y| {
            (area.x..area.x + area.width)
                .filter_map(|x| buf.cell((x, y)).map(|c| c.symbol().to_string()))
                .collect::<String>()
        })
        .collect();
    // Answers holds focus here, so its border is the heavy `┃` glyph.
    assert!(reversed.starts_with("┃SRV"), "highlighted: {reversed}");
}

#[test]
fn gone_row_carries_no_marker_or_findings() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    // A goodbye copy from another responder shares the live row's
    // identity: only the live row is marked.
    let mut gone = app.services[0]
        .answers
        .iter()
        .find(|r| r.rtype == 16)
        .unwrap()
        .clone();
    gone.source = "192.168.1.3:5353".parse().unwrap();
    gone.ttl = 0;
    app.services[0].answers.push(gone);
    let lines = answers_text(&app);
    let txt_rows: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.contains("▸ TXT"))
        .map(|(i, _)| i)
        .collect();
    assert_eq!(txt_rows.len(), 2);
    let (live, dead): (Vec<usize>, Vec<usize>) = txt_rows
        .into_iter()
        .partition(|&i| !lines[i].contains("192.168.1.3"));
    assert!(lines[live[0] + 1].contains("no-flush"));
    let warn = icon(anomalies::Severity::Warning);
    assert!(!lines[dead[0]].contains(warn), "{}", lines[dead[0]]);
    assert!(
        !lines
            .get(dead[0] + 1)
            .is_some_and(|l| l.contains("no-flush")),
        "{lines:#?}"
    );
}

#[test]
fn service_block_holds_rowless_findings_only_when_present() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    assert!(
        !answers_text(&app).iter().any(|l| l.starts_with("│service")),
        "no block without service-level findings"
    );
    ingest(
        &mut app,
        &raw_record("Test._http._tcp.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    let lines = answers_text(&app);
    let block = lines
        .iter()
        .position(|l| l.starts_with("│service"))
        .expect("service block");
    assert!(
        block_has(&lines, block, "unicast-style-response"),
        "{lines:#?}"
    );
    let first_record = lines.iter().position(|l| l.contains("PTR ")).unwrap();
    assert!(block < first_record, "block sits at the top");
}

#[test]
fn host_block_shows_host_findings_on_every_sibling() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    ingest(
        &mut app,
        &raw_record(
            "_ipp._tcp.local.",
            12,
            "PTR",
            "Other._ipp._tcp.local.",
            4500,
        ),
    );
    ingest(
        &mut app,
        &raw_record(
            "Other._ipp._tcp.local.",
            33,
            "SRV",
            "0 0 631 test.local.",
            120,
        ),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    app.evict_expired();
    for instance in ["Test", "Other"] {
        select_instance(&mut app, instance);
        let lines = answers_text(&app);
        let block = lines
            .iter()
            .position(|l| l.starts_with("│host test"))
            .unwrap_or_else(|| panic!("host block on {instance}: {lines:#?}"));
        assert!(
            block_has(&lines, block, "unicast-style-response"),
            "{lines:#?}"
        );
    }
    // Recorded once, under the host, in the dump's finding list.
    let hosts: Vec<_> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.kind == anomalies::AnomalyKind::UnicastStyleResponse)
        .map(|a| a.service)
        .collect();
    assert_eq!(hosts, vec!["test.local".to_string()]);
}

#[test]
fn badges_count_info_and_enumeration_findings() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
    app.ingest_event(&query_event(
        "_services._dns-sd._udp.local.",
        6,
        "TYPE6",
        false,
        Vec::new(),
        stub,
    ));
    let found = app.anomalies();
    let own = found
        .iter()
        .filter(|a| a.service == "Test._http._tcp.local")
        .count();
    let buf = render_to_buffer(&app, 160, 40);
    let hosts = rect_text(&buf, app.layout.left_rect.get());
    let warn = icon(anomalies::Severity::Warning);
    let info = icon(anomalies::Severity::Info);
    let test_row = hosts.lines().find(|l| l.contains("Test [")).unwrap();
    assert!(
        test_row.contains(&format!("[{warn} {own}]")),
        "info findings count, warning is the worst: {test_row}"
    );
    let enum_row = hosts.lines().find(|l| l.contains("[enum]")).unwrap();
    assert!(enum_row.contains(&format!("[{info} 1]")), "{enum_row}");
}

#[test]
fn pane_titles_count_shown_findings() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let target = app.display_detail().unwrap();
    let found = app.anomalies();
    let n = app
        .answers_layout(&target, &found)
        .iter()
        .filter(|l| matches!(l, AnswerLine::Finding { .. }))
        .count();
    assert!(n >= 2);
    let lines = answers_text(&app);
    let warn = icon(anomalies::Severity::Warning);
    assert!(
        lines[0].contains(&format!("· {warn} {n}")),
        "title: {}",
        lines[0]
    );
}

#[test]
fn unattributed_entry_lists_ownerless_findings_until_an_owner_appears() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    assert!(!app
        .display_items()
        .iter()
        .any(|it| matches!(it, DisplayItem::Unattributed)));
    ingest(
        &mut app,
        &raw_record("Late._http._tcp.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    let items = app.display_items();
    let pos = items
        .iter()
        .position(|it| matches!(it, DisplayItem::Unattributed))
        .expect("(unattributed) entry");
    assert!(matches!(
        &items[pos - 1],
        DisplayItem::Host { label } if label == UNATTRIBUTED_HOST
    ));
    // The header carries its own badge.
    let worst = app
        .anomalies()
        .into_iter()
        .filter(|a| a.service == anomalies::UNATTRIBUTED_SERVICE)
        .map(|a| a.severity)
        .max_by_key(|s| s.rank())
        .unwrap();
    let n = app
        .anomalies()
        .iter()
        .filter(|a| a.service == anomalies::UNATTRIBUTED_SERVICE)
        .count();
    let buf = render_to_buffer(&app, 160, 40);
    let hosts = rect_text(&buf, app.layout.left_rect.get());
    let header = hosts
        .lines()
        .find(|l| l.contains("(unattributed)"))
        .unwrap();
    assert!(
        header.contains(&format!("[{} {n}]", icon(worst))),
        "{header}"
    );
    // Selecting it lists the findings grouped by name.
    app.view_state.selected_display = pos;
    let lines = answers_text(&app);
    let block = lines
        .iter()
        .position(|l| l.starts_with("│Late._http._tcp.local."))
        .unwrap_or_else(|| panic!("{lines:#?}"));
    assert!(
        block_has(&lines, block, "unicast-style-response"),
        "{lines:#?}"
    );
    // Once the service appears, the finding moves and the entry goes.
    ingest(
        &mut app,
        &raw_record(
            "_http._tcp.local.",
            12,
            "PTR",
            "Late._http._tcp.local.",
            4500,
        ),
    );
    assert!(!app
        .display_items()
        .iter()
        .any(|it| matches!(it, DisplayItem::Unattributed)));
}

#[test]
fn sourced_finding_stays_on_its_responders_row() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    // A second responder sends the same TXT correctly (flush bit set):
    // the first one's no-flush finding must not land on it.
    let mut good = txt_record("a=1; b=2");
    good.source = "192.168.1.3:5353".parse().unwrap();
    good.flush_bit = true;
    ingest(&mut app, &good);
    let lines = answers_text(&app);
    let good_row = lines
        .iter()
        .position(|l| l.contains("TXT") && l.contains("192.168.1.3"))
        .expect("second responder's row");
    let warn = icon(anomalies::Severity::Warning);
    assert!(!lines[good_row].contains(warn), "{}", lines[good_row]);
    assert!(!lines[good_row + 1].contains("no-flush"), "{lines:#?}");
    let bad_row = lines
        .iter()
        .position(|l| l.contains("TXT") && l.contains("192.168.1.2"))
        .unwrap();
    assert!(lines[bad_row + 1].contains("no-flush"), "{lines:#?}");
}

#[test]
fn vanished_unattributed_row_does_not_panic_navigation() {
    let (mut app, pos) = app_with_unattributed();
    app.view_state.selected_display = pos;
    app.clamp_selection();
    // The sighting ages out between frames; no clamp runs before `k`.
    app.sightings.clear();
    assert!(app.view_state.selected_display >= app.display_items().len());
    app.move_selection(-1);
    assert!(app.view_state.selected_display < app.display_items().len());
    app.move_selection(1);
    assert!(app.view_state.selected_display < app.display_items().len());
}

#[test]
fn folding_unattributed_keeps_it_as_the_detail_target() {
    let (mut app, pos) = app_with_unattributed();
    assert!(matches!(
        app.display_detail(),
        Some(DetailTarget::Service(_))
    ));
    app.view_state.selected_display = pos;
    app.clamp_selection();
    app.toggle_collapse();
    assert!(matches!(
        app.display_items().get(app.view_state.selected_display),
        Some(DisplayItem::Host { label }) if label == UNATTRIBUTED_HOST
    ));
    assert!(
        matches!(app.display_detail(), Some(DetailTarget::Unattributed)),
        "the folded header keeps showing the unattributed findings"
    );
    // Selecting a service again replaces it.
    select_instance(&mut app, "Test");
    assert!(matches!(
        app.display_detail(),
        Some(DetailTarget::Service(_))
    ));
}

#[test]
fn entering_unattributed_resets_the_answers_viewport() {
    let (mut app, pos) = app_with_unattributed();
    app.layout.detail_offset.set(5);
    app.view_state.detail_free_scroll = true;
    app.view_state.selected_display = pos;
    app.clamp_selection();
    assert_eq!(app.layout.detail_offset.get(), 0);
    assert!(!app.view_state.detail_free_scroll);
}

#[test]
fn answers_click_hits_the_row_as_drawn() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    app.layout.detail_offset.set(0);
    // Draw a frame without the PTR's ttl-mismatch child: SRV sits on
    // table row 2 (srvc, PTR, SRV).
    let drawn: Vec<anomalies::Anomaly> = app
        .anomalies()
        .into_iter()
        .filter(|a| a.kind != anomalies::AnomalyKind::TtlMismatch)
        .collect();
    let backend = ratatui::backend::TestBackend::new(160, 40);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| crate::ui::draw_with_findings(f, &app, &drawn))
        .unwrap();
    let area = app.layout.answers_rect.get();
    // The live analyzer still has the PTR finding, which would put a
    // child row at table row 2; the click must follow the frame.
    app.click_answers(area.y + 2 + 2);
    match app.selected_detail_entry() {
        Some(DetailEntry::Record(r)) => assert_eq!(r.rtype, 33),
        _ => panic!("cursor on a record"),
    }
}

/// An app with one service and one ownerless sighting; returns the
/// `(unattributed)` row's display position.
fn app_with_unattributed() -> (App, usize) {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    ingest(
        &mut app,
        &raw_record("router.fritz.box.", 6, "TYPE6", "rdlength=30", 4500),
    );
    let pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Unattributed))
        .expect("(unattributed) entry");
    (app, pos)
}

#[test]
fn flooded_host_addresses_are_flagged_in_every_sibling_service() {
    // #407: the host's responder multicasts its A/AAAA as additionals
    // several times a second (RFC 6762 §6); both services on the host
    // show the finding on those rows.
    let mut app = knulp_app();
    for _ in 0..3 {
        ingest_packet(&mut app, packet(vec![a_knulp(), aaaa_knulp()]));
    }
    for instance in ["iTunes_Ctrl", "KNULP"] {
        select_instance(&mut app, instance);
        let target = app.display_detail().unwrap();
        let rows = target.ordered_answers();
        let flagged: Vec<u16> = shown(&app)
            .into_iter()
            .filter(|(a, _)| a.kind == anomalies::AnomalyKind::MulticastRateLimit)
            .filter_map(|(_, row)| row.map(|r| rows[r].rtype))
            .collect();
        assert!(
            flagged.contains(&1),
            "{instance}: A row flagged: {flagged:?}"
        );
        assert!(
            flagged.contains(&28),
            "{instance}: AAAA row flagged: {flagged:?}"
        );
    }
}
