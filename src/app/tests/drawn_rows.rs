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
    let drawn_pos = question_pos(&app, querier(1));
    ask(&mut app, "Test._http._tcp.local.", querier(9));
    assert_ne!(
        question_pos(&app, querier(1)),
        drawn_pos,
        "the new question shifts the list"
    );
    app.click_questions(area.y + line as u16);
    match app.selected_detail_entry() {
        Some(DetailEntry::Question { source, .. }) => {
            assert_eq!(source.to_string(), clicked, "the drawn querier")
        }
        _ => panic!("cursor on a question"),
    }
}

/// Position of `source`'s question in the displayed Questions list.
fn question_pos(app: &App, source: SocketAddr) -> Option<usize> {
    app.display_detail()?
        .ordered_questions()
        .iter()
        .position(|q| q.2 == source)
}

#[test]
fn click_on_a_question_aged_out_since_the_draw_selects_nothing() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    for i in 0..3 {
        ask(&mut app, "Test._http._tcp.local.", querier(i));
    }
    let buf = draw(&app);
    let area = app.layout.questions_rect.get();
    let lines = pane_lines(&buf, area);
    let gone = querier(1);
    let line = lines
        .iter()
        .position(|l| l.contains(&gone.to_string()))
        .unwrap_or_else(|| panic!("{gone} row: {lines:#?}"));
    // The drawn question leaves the window before the click.
    for q in app.services.iter_mut().flat_map(|s| s.questions.iter_mut()) {
        if q.2 == gone {
            q.3 = Instant::now()
                .checked_sub(QUESTION_WINDOW + Duration::from_secs(60))
                .unwrap_or_else(Instant::now);
        }
    }
    app.evict_expired();
    assert_eq!(question_pos(&app, gone), None, "aged out");
    let before = app.view_state.detail_selected;
    app.click_questions(area.y + line as u16);
    assert_eq!(
        app.view_state.detail_selected, before,
        "no other row is picked"
    );
}

#[test]
fn paging_matches_drawn_records_whatever_their_name_case() {
    // A replacing copy may differ in owner-name case only (#403): the
    // drawn row still counts as that record.
    let drawn = raw_record("Test._http._tcp.local.", 16, "TXT", "a=1", 120);
    let mut replaced = drawn.clone();
    replaced.name = "TEST._http._tcp.local.".to_string();
    let other = raw_record("Test._http._tcp.local.", 33, "SRV", "0 0 80 x.", 120);
    let rows = DrawnRows::new(
        vec![
            Some(DetailCursorKey::record(&drawn)),
            Some(DetailCursorKey::record(&other)),
        ],
        vec![3, 1],
    );
    assert_eq!(
        rows.lines_between_owners(
            &DetailCursorKey::record(&replaced),
            &DetailCursorKey::record(&other)
        ),
        Some(3)
    );
}
