// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #413: clicks hit the row as drawn, even after the list reorders ---

use super::*;

/// Draw one frame of the whole UI at a size that shows every row.
fn draw(app: &App) -> ratatui::buffer::Buffer {
    render_to_buffer(app, 160, 60)
}

#[test]
fn answers_click_selects_the_drawn_record_after_a_reorder() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let buf = draw(&app);
    let area = app.layout.answers_rect.get();
    let lines = pane_lines(&buf, area);
    let srv = lines
        .iter()
        .position(|l| l.starts_with("│SRV"))
        .unwrap_or_else(|| panic!("SRV row: {lines:#?}"));
    // An address record lands before the click: it sorts above SRV.
    ingest(&mut app, &addr(28, "fd00::9", "192.168.1.2:5353"));
    let reordered = app.display_detail().unwrap().ordered_answers();
    let srv_pos = reordered.iter().position(|r| r.rtype == 33).unwrap();
    let drawn_pos = lines[..srv]
        .iter()
        .filter(|l| l.contains("192.168.1.2:5353"))
        .count();
    assert_ne!(srv_pos, drawn_pos, "the reorder moves SRV in the list");
    app.click_answers(area.y + srv as u16);
    match app.selected_detail_entry() {
        Some(DetailEntry::Record(r)) => assert_eq!(r.rtype, 33, "the drawn SRV"),
        _ => panic!("cursor on a record"),
    }
}

#[test]
fn questions_click_selects_the_drawn_querier_after_a_reorder() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    for i in 0..3 {
        ask(&mut app, "Test._http._tcp.local.", querier(i));
    }
    let buf = draw(&app);
    let area = app.layout.questions_rect.get();
    let lines = pane_lines(&buf, area);
    let clicked = querier(1).to_string();
    let line = lines
        .iter()
        .position(|l| l.contains(&clicked))
        .unwrap_or_else(|| panic!("{clicked} row: {lines:#?}"));
    // A newer question lands before the click: newest first, it sorts
    // above every drawn row.
    ask(&mut app, "Test._http._tcp.local.", querier(9));
    app.click_questions(area.y + line as u16);
    match app.selected_detail_entry() {
        Some(DetailEntry::Question { source, .. }) => {
            assert_eq!(source.to_string(), clicked, "the drawn querier")
        }
        _ => panic!("cursor on a question"),
    }
}
