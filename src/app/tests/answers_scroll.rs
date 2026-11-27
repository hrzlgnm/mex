// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

// --- #406: rows above the first record stay reachable ---

use super::*;
use crossterm::event::KeyCode;

/// Frame size whose Answers pane is far shorter than the table.
const WIDTH: u16 = 160;
const HEIGHT: u16 = 24;

/// Test._http._tcp.local on test.local, with a host finding (a
/// unicast-style SOA sighting) and enough AAAA rows to overflow the
/// Answers viewport; Answers focused, cursor on the first record.
fn tall_service_with_host_finding() -> App {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    ingest(
        &mut app,
        &raw_record("test.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    for i in 1..=30 {
        ingest(
            &mut app,
            &raw_record("test.local.", 28, "AAAA", &format!("fd00::{i:x}"), 120),
        );
    }
    app.evict_expired();
    select_instance(&mut app, "Test");
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view_state.focus, Focus::Answers);
    app
}

/// Answers pane text at the test frame size, one line per row.
fn pane(app: &App) -> Vec<String> {
    let buf = render_to_buffer(app, WIDTH, HEIGHT);
    rect_text(&buf, app.layout.answers_rect.get())
        .lines()
        .map(str::to_string)
        .collect()
}

fn shows_host_block(lines: &[String]) -> bool {
    // Skip the border glyph: focused panes draw a heavy one.
    lines.iter().any(|l| {
        l.chars()
            .skip(1)
            .collect::<String>()
            .starts_with("host test")
    })
}

#[test]
fn home_after_end_shows_the_host_block_again() {
    let mut app = tall_service_with_host_finding();
    assert!(shows_host_block(&pane(&app)), "{:#?}", pane(&app));
    press(&mut app, KeyCode::End);
    let bottom = pane(&app);
    assert!(!shows_host_block(&bottom), "scrolled away: {bottom:#?}");
    press(&mut app, KeyCode::Home);
    let top = pane(&app);
    assert!(shows_host_block(&top), "host block back: {top:#?}");
    assert!(
        top.iter().any(|l| l.contains("unicast-style-response")),
        "its finding too: {top:#?}"
    );
}

#[test]
fn stepping_and_paging_up_to_the_first_record_show_the_host_block() {
    for (name, up) in [("k", KeyCode::Char('k')), ("PageUp", KeyCode::PageUp)] {
        let mut app = tall_service_with_host_finding();
        press(&mut app, KeyCode::End);
        // Every draw stores the clamped offset and viewport height the
        // next key press works from, as the main loop does between keys.
        pane(&app);
        // Enough presses to reach the first record and stop there.
        for _ in 0..40 {
            press(&mut app, up);
            pane(&app);
        }
        let top = pane(&app);
        assert!(shows_host_block(&top), "{name}: {top:#?}");
    }
}

#[test]
fn short_pane_keeps_the_first_record_in_view() {
    // End to end only: ratatui also keeps the selected row visible, so
    // the helper's cap itself is pinned by its unit tests in `ui.rs`.
    let mut app = tall_service_with_host_finding();
    // Answers rows above the first record: srvc, host block, finding.
    let leading = 3;
    let mut short = HEIGHT;
    // Shrink the frame until the pane is shorter than the leading rows
    // plus the first record.
    loop {
        render_to_buffer(&app, WIDTH, short);
        if app.layout.record_viewport.get() <= leading {
            break;
        }
        short -= 1;
    }
    press(&mut app, KeyCode::End);
    render_to_buffer(&app, WIDTH, short);
    press(&mut app, KeyCode::Home);
    let buf = render_to_buffer(&app, WIDTH, short);
    let text = rect_text(&buf, app.layout.answers_rect.get());
    assert!(text.contains("fd00::1 "), "first record stays: {text}");
}

#[test]
fn expanding_the_last_record_still_reveals_its_pairs() {
    let mut app = tall_service_with_host_finding();
    ingest(&mut app, &txt_record("a=1; b=2; c=3"));
    app.evict_expired();
    // Rows sort by type name, so TXT is the last record.
    press(&mut app, KeyCode::End);
    assert!(pane(&app).iter().any(|l| l.contains("▸ TXT")));
    press(&mut app, KeyCode::Enter);
    let lines = pane(&app);
    assert!(lines.iter().any(|l| l.contains("▾ TXT")), "{lines:#?}");
    assert!(
        lines.iter().any(|l| l.contains("└─ c=3")),
        "last pair in view: {lines:#?}"
    );
}

/// Text of each leading block's header row (border glyph skipped).
fn block_rows(lines: &[String]) -> Vec<String> {
    lines
        .iter()
        .map(|l| l.chars().skip(1).collect::<String>())
        .filter(|l| {
            ["srvc", "subt", "service", "host "]
                .iter()
                .any(|h| l.starts_with(h))
        })
        .map(|l| l.split_whitespace().take(2).collect::<Vec<_>>().join(" "))
        .collect()
}

#[test]
fn home_brings_back_every_leading_block() {
    let mut app = tall_service_with_host_finding();
    ingest(
        &mut app,
        &raw_record(
            "_printer._sub._http._tcp.local.",
            12,
            "PTR",
            "Test._http._tcp.local.",
            120,
        ),
    );
    // A second SRV target, with its own host finding.
    let mut srv = raw_record(
        "Test._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 other.local.",
        120,
    );
    srv.source = "192.168.1.3:5353".parse().unwrap();
    ingest(&mut app, &srv);
    ingest(
        &mut app,
        &raw_record("other.local.", 6, "TYPE6", "rdlength=22", 4500),
    );
    app.evict_expired();
    // No analyzer kind is rowless for this service; inject one so the
    // `service` block shows.
    let mut found = app.anomalies();
    found.push(anomalies::Anomaly {
        kind: anomalies::AnomalyKind::TypeFormat,
        severity: anomalies::Severity::Info,
        service: "Test._http._tcp.local".to_string(),
        record_name: None,
        rtype: None,
        rtype_str: None,
        rdata: None,
        source: None,
        message: "injected service finding".to_string(),
        rfc: "RFC 6763 §7",
        requirement: "",
        response: None,
        responders: Vec::new(),
    });
    // Tall enough for every leading row (the host findings wrap, #410)
    // plus the first record, still far shorter than the table.
    let pane_with = |app: &App| -> Vec<String> {
        let mut term =
            ratatui::Terminal::new(ratatui::backend::TestBackend::new(WIDTH, 40)).unwrap();
        term.draw(|f| crate::ui::draw_with_findings(f, app, &found))
            .unwrap();
        rect_text(term.backend().buffer(), app.layout.answers_rect.get())
            .lines()
            .map(str::to_string)
            .collect()
    };
    let expected = [
        "srvc _http._tcp.local",
        "subt _printer",
        "service",
        "host other",
        "host test",
    ];
    let initial = block_rows(&pane_with(&app));
    for header in expected {
        assert!(
            initial.iter().any(|b| b.starts_with(header)),
            "{header} at start: {initial:#?}"
        );
    }
    press(&mut app, KeyCode::End);
    assert!(block_rows(&pane_with(&app)).is_empty(), "scrolled away");
    press(&mut app, KeyCode::Home);
    let top = pane_with(&app);
    assert_eq!(block_rows(&top), initial, "{top:#?}");
    assert!(
        top.iter().any(|l| l.contains("injected service finding")),
        "{top:#?}"
    );
    assert!(
        top.iter().any(|l| l.contains("fd00::1 ")),
        "first record: {top:#?}"
    );
}
