// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn ordered_answers_sorts_sources_numerically() {
    // Same TXT from two responders: rows group by type, then by
    // source address in numeric (not string) order.
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    for ip in ["10.0.0.10", "10.0.0.2"] {
        let mut rec = txt_record("a=1");
        rec.source = format!("{ip}:5353").parse().unwrap();
        ingest(&mut app, &rec);
    }
    let sources: Vec<_> = app.services[0]
        .ordered_answers()
        .into_iter()
        .filter(|r| r.rtype == 16)
        .map(|r| r.source.to_string())
        .collect();
    assert_eq!(sources, ["10.0.0.2:5353", "10.0.0.10:5353"]);
}

#[test]
fn status_popup_shows_while_fresh() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    assert!(app.status_popup().is_none());
    let shown = |app: &App, text: &str| screen(app, 100, 30).iter().any(|l| l.contains(text));
    let msg = "Dump saved: probe-popup.json";
    assert!(!shown(&app, msg));
    app.status_msg = Some((msg.to_string(), Instant::now()));
    assert_eq!(app.status_popup().as_deref(), Some(msg));
    assert!(shown(&app, msg), "drawn while fresh");
    // Expired after 3 s even without a key.
    app.status_msg = Some((msg.to_string(), Instant::now() - Duration::from_secs(4)));
    assert!(!shown(&app, msg), "gone after 3 s");
    app.status_msg = Some((msg.to_string(), Instant::now()));
    // Any key dismisses it.
    let plain = KeyEvent {
        code: KeyCode::Char('x'),
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(&plain);
    assert!(app.status_popup().is_none());
    assert!(!shown(&app, msg), "dismissed by a key");
}

#[test]
fn enum_answers_file_on_selectable_row() {
    let mut app = App::new().unwrap();
    assert_eq!(app.enum_entries.len(), 1);
    ingest(
        &mut app,
        &raw_record(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_http._tcp.local.",
            120,
        ),
    );
    assert!(app.scheduler.known_types().contains("_http._tcp.local"));
    assert_eq!(app.enum_entries[0].answers.len(), 1);
    assert_eq!(app.group_labels()[0], "(enumeration)");
    // Diagnostics carry a per-name row for the enumeration name.
    let rows = app.diagnostics_rows();
    assert!(rows.iter().any(|(k, _)| k.contains("_dns-sd._udp")));
}

#[test]
fn header_falls_back_to_last_selected_kind() {
    let mut app = two_group_app();
    select_instance(&mut app, "Shell");
    // Select the enumeration row, then collapse its group and park
    // on the collapsed header.
    let enum_pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Enum { .. }))
        .expect("enum row");
    app.view_state.selected_display = enum_pos;
    app.clamp_selection();
    assert!(app.selected_enum().is_some());
    app.collapsed_hosts.insert(ENUM_HOST.to_string());
    let header_pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Host { label } if label == ENUM_HOST))
        .expect("enum header");
    app.view_state.selected_display = header_pos;
    app.clamp_selection();
    assert!(app.selected_service().is_none());
    assert!(app.selected_enum().is_none());
    let target = app.display_detail().expect("sticky target survives header");
    assert!(
        matches!(target, DetailTarget::Enum(_)),
        "collapsed header must show the last selected kind, not a stale service"
    );
}

#[test]
fn groups_by_hostname_with_unknown_last() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    // Second service without hostname yet: instance known via PTR only
    // would normally sit in pending; force a service with empty host.
    app.services.push(ServiceEntry {
        instance: "Lonely".to_string(),
        service_type: "_http._tcp.local".to_string(),
        hostname: String::new(),
        port: 0,
        subtypes: Vec::new(),
        answers: Vec::new(),
        questions: Vec::new(),
        questions_dropped: 0,
        last_seen: Instant::now(),
        is_active: true,
        last_event: None,
    });
    app.evict_expired();
    let labels: Vec<String> = app
        .display_items()
        .into_iter()
        .filter_map(|it| match it {
            DisplayItem::Host { label } => Some(label),
            _ => None,
        })
        .collect();
    assert_eq!(
        labels,
        vec![
            "(enumeration)".to_string(),
            "test.local".to_string(),
            String::new()
        ]
    );
    assert_eq!(app.host_display_name("test.local"), "test");
    assert_eq!(app.host_display_name(""), "(unknown host)");
    assert_eq!(app.host_service_count("test.local"), 1);
    assert_eq!(app.host_service_count(""), 1);
}

#[test]
fn host_display_name_strips_redundant_local_suffix() {
    let app = App::new().unwrap();
    assert_eq!(app.host_display_name("printer.local"), "printer");
    assert_eq!(app.host_display_name("printer.local."), "printer");
    assert_eq!(app.host_display_name("printer.LOCAL"), "printer");
    // Bare `local` or `local` mid-name is not a suffix: untouched.
    assert_eq!(app.host_display_name("local"), "local");
    assert_eq!(app.host_display_name("mylocal"), "mylocal");
    assert_eq!(app.host_display_name("local.domain"), "local.domain");
}

#[test]
fn host_addresses_ipv4_first_live_only() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    // A + AAAA for the same host, plus a duplicate and an expired row.
    ingest(
        &mut app,
        &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
    );
    ingest(
        &mut app,
        &raw_record("test.local.", 28, "AAAA", "fe80::1", 120),
    );
    ingest(&mut app, &raw_record("test.local.", 1, "A", "10.0.0.9", 0));
    let addrs = app.host_addresses("test.local");
    assert_eq!(
        addrs,
        vec!["192.168.1.10".to_string(), "fe80::1".to_string()]
    );
    // (+N) suffix shows additional addresses beyond the primary.
    assert_eq!(addrs.len() - 1, 1);
}

#[test]
fn tiny_terminal_renders_every_right_pane() {
    let app = two_group_app();
    for (width, height) in [(100, 30), (60, 12), (40, 8)] {
        let buf = render_to_buffer(&app, width, height);
        // Every right-stack pane keeps a visible row and shows its
        // own title inside its own rect — not just somewhere in the
        // buffer.
        for (rect, title) in [
            (&app.layout.answers_rect, "Answers"),
            (&app.layout.questions_rect, "Questions"),
            (&app.layout.hex_rect, "Raw Packet"),
        ] {
            let area = rect.get();
            assert!(area.height >= 1, "{width}x{height}: every pane keeps a row");
            assert!(
                rect_text(&buf, area).contains(title),
                "{width}x{height} must show the {title} pane in place"
            );
        }
    }
}

#[test]
fn empty_right_panes_keep_focus_border() {
    let mut app = App::new().unwrap();
    assert!(
        app.display_detail().is_none(),
        "a fresh app exercises the right-pane empty states"
    );
    let rect_for = |app: &App, focus: Focus| {
        let layout = &app.layout;
        match focus {
            Focus::Answers => layout.answers_rect.get(),
            Focus::Questions => layout.questions_rect.get(),
            Focus::Hex => layout.hex_rect.get(),
            Focus::Services => unreachable!(),
        }
    };
    // Each empty-state branch must keep a border so the focus cue survives
    // when there is no target/packet to draw.
    for focus in [Focus::Answers, Focus::Questions, Focus::Hex] {
        app.view_state.focus = focus;
        let buf = render_to_buffer(&app, 100, 30);
        let area = rect_for(&app, focus);
        let corner = buf
            .cell((area.x, area.y))
            .map(|c| c.symbol())
            .unwrap_or_default();
        assert_eq!(
            corner, "┏",
            "{focus:?} empty state must have a thick border"
        );
        assert!(
            rect_text(&buf, area).contains(&format!("{focus:?}")),
            "{focus:?} empty state must keep its title"
        );
    }
    // Unfocused empty panes revert to the light border.
    app.view_state.focus = Focus::Services;
    let buf = render_to_buffer(&app, 100, 30);
    for focus in [Focus::Answers, Focus::Questions, Focus::Hex] {
        let area = rect_for(&app, focus);
        let corner = buf
            .cell((area.x, area.y))
            .map(|c| c.symbol())
            .unwrap_or_default();
        assert_eq!(
            corner, "┌",
            "{focus:?} empty state must have a plain border"
        );
    }
}

/// Every border-ring cell of a pane: `(col, row)` pairs.
fn ring_cells(r: ratatui::layout::Rect) -> Vec<(u16, u16)> {
    let mut cells = Vec::new();
    for col in r.x..r.x + r.width {
        cells.push((col, r.y));
        cells.push((col, r.y + r.height - 1));
    }
    for row in r.y..r.y + r.height {
        cells.push((r.x, row));
        cells.push((r.x + r.width - 1, row));
    }
    cells
}

/// A pane's border ring plus whether it currently holds focus.
fn pane_rings(app: &App) -> Vec<(&'static str, ratatui::layout::Rect, bool)> {
    let focus = app.view_state.focus;
    vec![
        (
            "Hosts",
            app.layout.left_rect.get(),
            focus == Focus::Services,
        ),
        (
            "Answers",
            app.layout.answers_rect.get(),
            focus == Focus::Answers,
        ),
        (
            "Questions",
            app.layout.questions_rect.get(),
            focus == Focus::Questions,
        ),
        ("Hex", app.layout.hex_rect.get(), focus == Focus::Hex),
    ]
}

/// Cells of a border ring that are plain border: the top row carries
/// title spans whose colors are content-driven, so it is excluded.
fn plain_ring_cells(r: ratatui::layout::Rect) -> Vec<(u16, u16)> {
    ring_cells(r)
        .into_iter()
        .filter(|&(col, row)| !(row == r.y && col > r.x && col < r.x + r.width - 1))
        .collect()
}

/// A border cell must sit at a rest color (focus white or gray), and
/// never at the resize glow color unless its pane is listed as glowing.
fn assert_rest_border_colors(
    app: &App,
    buf: &ratatui::buffer::Buffer,
    glowing: &[&str],
    context: &str,
) {
    use ratatui::style::Color;
    for (name, rect, focused) in pane_rings(app) {
        for (col, row) in plain_ring_cells(rect) {
            let fg = buf.cell((col, row)).map(|c| c.fg);
            if glowing.contains(&name) {
                assert_eq!(
                    fg,
                    Some(Color::Cyan),
                    "{context}: {name} border at {col},{row} must keep the hover glow"
                );
            } else {
                let want = if focused { Color::White } else { Color::Gray };
                assert_eq!(
                    fg, Some(want),
                    "{context}: {name} border at {col},{row} must sit at a rest color, not the drag glow"
                );
            }
        }
    }
}

#[test]
fn mouse_up_without_motion_ends_the_resize_glow() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    let down = |column, row| MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    };
    let drag = |column, row| MouseEvent {
        kind: MouseEventKind::Drag(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    };
    let up = |column, row| MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    };
    // Release away from any seam, with no motion event afterwards: the
    // very next frame must show the rest colors, not the drag glow.
    let mut app = two_group_app();
    app.view_state.focus = Focus::Answers;
    render_to_buffer(&app, 100, 40);
    let left = app.layout.left_rect.get();
    app.handle_mouse(&down(left.x + left.width - 1, left.y + 5));
    app.handle_mouse(&drag(left.x + left.width - 6, left.y + 5));
    app.handle_mouse(&up(2, left.y + 1));
    let buf = render_to_buffer(&app, 100, 40);
    assert_rest_border_colors(&app, &buf, &[], "release off-seam without motion");
    // Release on the Questions/Hex seam itself: the pointer rests on a
    // grabbable seam, so that seam legitimately keeps the hover glow
    // while the other panes return to their own colors.
    let mut app = two_group_app();
    app.view_state.focus = Focus::Answers;
    render_to_buffer(&app, 100, 40);
    let answers = app.layout.answers_rect.get();
    app.handle_mouse(&down(answers.x + 5, app.layout.hex_rect.get().y));
    app.handle_mouse(&drag(answers.x + 5, app.layout.hex_rect.get().y + 3));
    render_to_buffer(&app, 100, 40);
    let hex = app.layout.hex_rect.get();
    app.handle_mouse(&up(answers.x + 5, hex.y));
    let buf = render_to_buffer(&app, 100, 40);
    assert_rest_border_colors(
        &app,
        &buf,
        &["Questions", "Hex"],
        "release on the lower seam",
    );
}

#[test]
fn synthetic_rows_and_hostnames_render_italic() {
    use ratatui::style::Modifier;
    let app = two_group_app();
    let buf = render_to_buffer(&app, 100, 30);
    // Host group header: the display name after the glyph is italic,
    // the count and addresses are not.
    let area = app.layout.left_rect.get();
    let mut header = None;
    for y in (area.y + 1)..(area.y + area.height.saturating_sub(1)) {
        let mut row = String::new();
        for x in (area.x + 1)..(area.x + area.width.saturating_sub(1)) {
            row.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or_default());
        }
        if row.starts_with("\u{25be} ") || row.starts_with("\u{25b8} ") {
            header = Some((y, row));
            break;
        }
    }
    let (y, row) = header.expect("host header row");
    let name_cell = buf.cell((area.x + 3, y)).expect("display-name cell");
    assert!(
        name_cell.modifier.contains(Modifier::ITALIC),
        "hostname should be italic"
    );
    let paren = row.rfind(" (").expect("header count");
    let count_cell = buf
        .cell((area.x + 1 + paren as u16 + 1, y))
        .expect("count cell");
    assert!(
        !count_cell.modifier.contains(Modifier::ITALIC),
        "only the hostname is italic"
    );
    // Detail table synthetic rows (`srvc`, …) are italic throughout.
    let area = app.layout.answers_rect.get();
    let label_cell = buf.cell((area.x + 1, area.y + 2)).expect("srvc cell");
    assert_eq!(label_cell.symbol(), "s");
    assert!(
        label_cell.modifier.contains(Modifier::ITALIC),
        "synthetic rows should be italic"
    );
}

#[test]
fn txt_children_render_upright() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::style::Modifier;
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
    let buf = render_to_buffer(&app, 100, 30);
    let area = app.layout.answers_rect.get();
    // Expanded TXT pair rows show verbatim wire content: green like
    // the header rows, but never italic.
    let mut pair = None;
    for y in (area.y + 1)..(area.y + area.height.saturating_sub(1)) {
        let mut row = String::new();
        for x in (area.x + 1)..(area.x + area.width.saturating_sub(1)) {
            row.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or_default());
        }
        if (row.contains("├─") || row.contains("└─")) && row.contains("a=1") {
            pair = Some((y, row));
            break;
        }
    }
    let (y, _) = pair.expect("expanded TXT pair row");
    let cell = buf.cell((area.x + 1, y)).expect("pair cell");
    assert!(
        !cell.modifier.contains(Modifier::ITALIC),
        "wire content stays upright"
    );
    assert_eq!(
        cell.fg,
        ratatui::style::Color::Green,
        "pair rows keep the info color, got: {:?}",
        cell.fg
    );
}
