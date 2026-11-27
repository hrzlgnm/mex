// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #410: long findings wrap onto multiple lines ---

use super::*;

/// A message far wider than any pane in these tests.
const LONG: &str = "alpha bravo charlie delta echo foxtrot golf hotel india juliett \
     kilo lima mike november oscar papa quebec romeo sierra tango uniform \
     victor whiskey xray yankee zulu-end";

/// Draw one frame with `found` injected; returns the buffer.
fn frame(app: &App, found: &[anomalies::Anomaly], w: u16, h: u16) -> ratatui::buffer::Buffer {
    let backend = ratatui::backend::TestBackend::new(w, h);
    let mut term = ratatui::Terminal::new(backend).unwrap();
    term.draw(|f| crate::ui::draw_with_findings(f, app, found))
        .unwrap();
    term.backend().buffer().clone()
}

fn pane_lines(buf: &ratatui::buffer::Buffer, area: ratatui::layout::Rect) -> Vec<String> {
    rect_text(buf, area).lines().map(str::to_string).collect()
}

/// The live findings with the `kind` one's message replaced by `msg`.
fn with_message(app: &App, kind: anomalies::AnomalyKind, msg: &str) -> Vec<anomalies::Anomaly> {
    let mut found = app.anomalies();
    found
        .iter_mut()
        .find(|a| a.kind == kind)
        .unwrap_or_else(|| panic!("expected a {kind} finding"))
        .message = msg.to_string();
    found
}

/// Char column where `needle` starts in `line`.
fn col(line: &str, needle: &str) -> usize {
    line[..line.find(needle).expect(needle)].chars().count()
}

/// The finding block starting at the line holding `head`: that line and
/// every following line indented to the same text column, joined by
/// single spaces.
fn finding_block(lines: &[String], head: &str) -> (usize, Vec<String>) {
    let first = lines.iter().position(|l| l.contains(head)).expect(head);
    let start = col(&lines[first], head);
    let mut block = vec![lines[first].chars().skip(start).collect::<String>()];
    for l in &lines[first + 1..] {
        let chars: Vec<char> = l.chars().collect();
        // Continuation: blank up to the text column, text right at it.
        let lead_blank = chars[1..start].iter().all(|c| *c == ' ');
        if !lead_blank || chars.get(start).is_none_or(|c| *c == ' ') {
            break;
        }
        block.push(chars[start..].iter().collect());
    }
    // Drop the right border and padding.
    let block = block
        .into_iter()
        .map(|s| s.trim_end_matches(['│', '┃', ' ']).to_string())
        .collect();
    (first, block)
}

#[test]
fn long_record_finding_wraps_under_its_row() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let found = with_message(&app, anomalies::AnomalyKind::NoFlush, LONG);
    let a = found
        .iter()
        .find(|a| a.kind == anomalies::AnomalyKind::NoFlush)
        .unwrap();
    let buf = frame(&app, &found, 120, 40);
    let lines = pane_lines(&buf, app.layout.answers_rect.get());
    let (first, block) = finding_block(&lines, "no-flush");
    assert!(block.len() > 1, "wrapped onto more lines: {lines:#?}");
    let expected = format!(
        "no-flush TXT Test._http._tcp.local.: {LONG} ({}, {})",
        a.rfc, a.requirement
    );
    assert_eq!(block.join(" "), expected, "nothing clipped: {lines:#?}");
    // The TXT record row sits right above; the row after the block is
    // the next table row, not more of the finding.
    assert!(lines[first - 1].contains("TXT"));
}

#[test]
fn short_finding_stays_one_line() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let found = with_message(&app, anomalies::AnomalyKind::NoFlush, "short");
    let buf = frame(&app, &found, 160, 40);
    let lines = pane_lines(&buf, app.layout.answers_rect.get());
    let (_, block) = finding_block(&lines, "no-flush");
    assert_eq!(block.len(), 1, "{lines:#?}");
}

#[test]
fn narrower_pane_wraps_onto_more_lines() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let found = with_message(&app, anomalies::AnomalyKind::NoFlush, LONG);
    let count = |w| {
        let buf = frame(&app, &found, w, 40);
        let lines = pane_lines(&buf, app.layout.answers_rect.get());
        finding_block(&lines, "no-flush").1.len()
    };
    let (wide, narrow) = (count(220), count(110));
    assert!(narrow > wide, "{narrow} lines at 110, {wide} at 220");
}

#[test]
fn word_wider_than_the_line_is_broken() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let word = "x".repeat(150);
    let found = with_message(&app, anomalies::AnomalyKind::NoFlush, &word);
    let buf = frame(&app, &found, 120, 40);
    let lines = pane_lines(&buf, app.layout.answers_rect.get());
    let (_, block) = finding_block(&lines, "no-flush");
    assert!(block.concat().contains(&word), "{lines:#?}");
}

#[test]
fn finding_taller_than_the_pane_is_cut_with_an_ellipsis() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let long = [LONG; 8].join(" ");
    let found = with_message(&app, anomalies::AnomalyKind::NoFlush, &long);
    // Park the cursor on TXT so its finding is pulled into view.
    let buf = frame(&app, &found, 100, 24);
    let area = app.layout.answers_rect.get();
    let lines = pane_lines(&buf, area);
    let (_, block) = finding_block(&lines, "no-flush");
    let viewport = usize::from(area.height) - 3;
    assert!(block.len() <= viewport, "{lines:#?}");
    assert!(
        block.last().unwrap().ends_with('…'),
        "cut shows: {lines:#?}"
    );
}

#[test]
fn tiny_panes_never_panic() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let found = with_message(&app, anomalies::AnomalyKind::NoFlush, LONG);
    for w in 1..=40 {
        for h in [1, 3, 5, 9] {
            frame(&app, &found, w, h);
        }
    }
}

#[test]
fn click_on_a_wrapped_line_selects_its_record() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let found = with_message(&app, anomalies::AnomalyKind::TtlMismatch, LONG);
    let buf = frame(&app, &found, 120, 40);
    let area = app.layout.answers_rect.get();
    let lines = pane_lines(&buf, area);
    let (first, block) = finding_block(&lines, "ttl-mismatch");
    assert!(block.len() > 2, "{lines:#?}");
    let rtype = |app: &App| match app.selected_detail_entry() {
        Some(DetailEntry::Record(r)) => r.rtype,
        _ => panic!("cursor on a record"),
    };
    // Third line of the PTR's finding: the PTR.
    app.click_answers(area.y + (first + 2) as u16);
    assert_eq!(rtype(&app), 12);
    // First line after the finding: the next record (SRV), not a line
    // counted as if the finding were one row tall.
    app.click_answers(area.y + (first + block.len()) as u16);
    assert_eq!(rtype(&app), 33, "{lines:#?}");
}

#[test]
fn page_down_moves_one_viewport_of_drawn_lines() {
    use crossterm::event::KeyCode;
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    // A PTR finding cut at the viewport: PTR plus it fill one page.
    let long = [LONG; 8].join(" ");
    let found = with_message(&app, anomalies::AnomalyKind::TtlMismatch, &long);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view_state.focus, Focus::Answers);
    press(&mut app, KeyCode::Home);
    frame(&app, &found, 100, 24);
    let viewport = app.layout.record_viewport.get();
    assert!(viewport > 3, "room for more than three records");
    press(&mut app, KeyCode::PageDown);
    // One record per viewport line would run to TXT; drawn, the next
    // page starts at SRV.
    match app.selected_detail_entry() {
        Some(DetailEntry::Record(r)) => assert_eq!(r.rtype, 33),
        _ => panic!("cursor on a record"),
    }
}

/// The service app with a TXT question from a foreign querier and an
/// injected finding of `msg` on it.
fn questioned_app(msg: &str) -> (App, Vec<anomalies::Anomaly>) {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let querier: SocketAddr = "192.168.1.77:5353".parse().unwrap();
    app.ingest_event(&query_event(
        "Test._http._tcp.local.",
        16,
        "TXT",
        false,
        Vec::new(),
        querier,
    ));
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
        message: msg.to_string(),
        rfc: "RFC 6762 §5",
        requirement: "",
        response: None,
        responders: Vec::new(),
    });
    (app, found)
}

#[test]
fn long_question_finding_wraps_and_clicks_select_its_question() {
    let (mut app, found) = questioned_app(LONG);
    let buf = frame(&app, &found, 120, 60);
    let area = app.layout.questions_rect.get();
    let lines = pane_lines(&buf, area);
    let (first, block) = finding_block(&lines, "unsupported-question");
    assert!(block.len() > 1, "{lines:#?}");
    assert!(
        block.join(" ").ends_with("zulu-end (RFC 6762 §5)"),
        "{lines:#?}"
    );
    app.click_questions(area.y + (first + 1) as u16);
    match app.selected_detail_entry() {
        Some(DetailEntry::Question { source, .. }) => {
            assert_eq!(source.to_string(), "192.168.1.77:5353")
        }
        _ => panic!("cursor on the question"),
    }
}

#[test]
fn unsourced_block_finding_wraps_across_source_and_data() {
    let mut app = super::conflicting_answers::disagreeing_mesh();
    select_instance(&mut app, "Fritzel");
    let found = with_message(&app, anomalies::AnomalyKind::ConflictingAnswers, LONG);
    let buf = frame(&app, &found, 140, 60);
    let lines = pane_lines(&buf, app.layout.answers_rect.get());
    let (_, block) = finding_block(&lines, "conflicting-answers");
    assert!(block.len() > 1, "{lines:#?}");
    assert!(block.join(" ").contains("zulu-end (RFC"), "{lines:#?}");
    // Starts in SOURCE, so it is wider than RDATA alone.
    let source_col = col(&lines[1], "SOURCE");
    let head = lines
        .iter()
        .find(|l| l.contains("conflicting-answers"))
        .unwrap();
    assert_eq!(col(head, "conflicting-answers"), source_col, "{lines:#?}");
}
