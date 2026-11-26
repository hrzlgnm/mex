// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! The Answers pane's SECT column (#399): which DNS section of the latest
//! response carried each record row.

use super::*;

/// Character column where `needle` starts in `line`.
fn col(line: &str, needle: &str) -> usize {
    line[..line
        .find(needle)
        .unwrap_or_else(|| panic!("{needle:?} in {line:?}"))]
        .chars()
        .count()
}

fn header(lines: &[String]) -> &str {
    lines
        .iter()
        .find(|l| l.contains("FLUSH"))
        .unwrap_or_else(|| panic!("{lines:#?}"))
}

/// The line of the record row whose RDATA contains `rdata`.
fn row<'a>(lines: &'a [String], rdata: &str) -> &'a str {
    lines
        .iter()
        .find(|l| l.contains(rdata))
        .unwrap_or_else(|| panic!("{rdata:?} in {lines:#?}"))
}

/// The SECT cell of `line`, trimmed, read under the header's SECT column.
fn sect_cell(lines: &[String], line: &str) -> String {
    let start = col(header(lines), "SECT");
    line.chars()
        .skip(start)
        .take(4)
        .collect::<String>()
        .trim()
        .to_string()
}

fn app_with_sections(srv: browse::RecordSection, a: browse::RecordSection) -> App {
    let mut app = App::new().unwrap();
    let ptr = ptr_record(120);
    let mut srv_rec = srv_record(120);
    srv_rec.section = srv;
    let mut a_rec = raw_record("test.local.", 1, "A", "192.168.1.2", 120);
    a_rec.flush_bit = true;
    a_rec.section = a;
    ingest_packet(&mut app, packet(vec![ptr, srv_rec, a_rec]));
    app.evict_expired();
    select_instance(&mut app, "Test");
    app
}

#[test]
fn header_puts_sect_between_flush_and_source() {
    let app = app_with_sections(
        browse::RecordSection::Answer,
        browse::RecordSection::Additional,
    );
    let lines = answers_text(&app);
    let h = header(&lines);
    assert!(col(h, "FLUSH") < col(h, "SECT"), "{h}");
    assert!(col(h, "SECT") < col(h, "SOURCE"), "{h}");
}

#[test]
fn record_rows_show_their_section() {
    let app = app_with_sections(
        browse::RecordSection::Authority,
        browse::RecordSection::Additional,
    );
    let lines = answers_text(&app);
    assert_eq!(
        sect_cell(&lines, row(&lines, "Test._http._tcp.local.")),
        "ans"
    );
    assert_eq!(sect_cell(&lines, row(&lines, "0 0 80 test.local.")), "auth");
    assert_eq!(sect_cell(&lines, row(&lines, "192.168.1.2 ")), "add");
}

#[test]
fn section_follows_the_latest_copy() {
    let mut app = app_with_sections(
        browse::RecordSection::Additional,
        browse::RecordSection::Additional,
    );
    let mut srv = srv_record(120);
    srv.section = browse::RecordSection::Answer;
    ingest(&mut app, &srv);
    let lines = answers_text(&app);
    let srv_rows: Vec<_> = lines
        .iter()
        .filter(|l| l.contains("0 0 80 test.local."))
        .collect();
    assert_eq!(srv_rows.len(), 1, "one row per record: {lines:#?}");
    assert_eq!(sect_cell(&lines, srv_rows[0]), "ans");
}

#[test]
fn info_rows_leave_sect_blank() {
    let app = app_with_sections(browse::RecordSection::Answer, browse::RecordSection::Answer);
    let lines = answers_text(&app);
    let srvc = lines
        .iter()
        .find(|l| l.contains("srvc"))
        .unwrap_or_else(|| panic!("{lines:#?}"));
    assert_eq!(sect_cell(&lines, srvc), "");
}

#[test]
fn sourced_finding_rows_keep_source_and_message_columns() {
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
    app.view_state.selected_display = pos;
    app.clamp_selection();
    let lines = answers_text(&app);
    let h = header(&lines);
    let finding = lines
        .iter()
        .find(|l| l.contains("192.168.1.2:5353"))
        .unwrap_or_else(|| panic!("{lines:#?}"));
    assert_eq!(
        col(finding, "192.168.1.2:5353"),
        col(h, "SOURCE"),
        "{lines:#?}"
    );
    let message_col = finding
        .char_indices()
        .nth(col(h, "RDATA"))
        .map(|(i, _)| &finding[i..])
        .unwrap_or("");
    assert!(
        !message_col.trim().is_empty() && !message_col.starts_with(' '),
        "message starts under RDATA: {lines:#?}"
    );
}

#[test]
fn expanded_txt_pairs_span_the_whole_row() {
    let mut app = App::new().unwrap();
    let long = format!("a={}; b=2", "x".repeat(90));
    service_with_txt(&mut app, &long);
    assert!(app.toggle_txt_expanded());
    let lines = answers_text(&app);
    assert!(
        lines
            .iter()
            .any(|l| l.contains(&format!("├─ a={}", "x".repeat(90)))),
        "{lines:#?}"
    );
}

/// The header line of the Answers pane drawn at `width` columns, and
/// the pane's inner width.
fn header_at(app: &App, width: u16) -> (String, u16) {
    let buf = render_to_buffer(app, width, 40);
    let area = app.layout.answers_rect.get();
    let text = rect_text(&buf, area);
    let header = text
        .lines()
        .find(|l| l.contains("TYPE"))
        .unwrap_or_else(|| panic!("{text}"))
        .to_string();
    (header, area.width - 2)
}

#[test]
fn narrow_pane_drops_sect_and_keeps_ttl_whole() {
    let app = app_with_sections(
        browse::RecordSection::Answer,
        browse::RecordSection::Additional,
    );
    let buf = render_to_buffer(&app, 80, 24);
    let lines: Vec<String> = rect_text(&buf, app.layout.answers_rect.get())
        .lines()
        .map(str::to_string)
        .collect();
    let h = header(&lines);
    assert!(!h.contains("SECT"), "{lines:#?}");
    let srv = row(&lines, "0 0 80 test.local.");
    assert!(srv.contains("2m00s") || srv.contains("1m59s"), "{lines:#?}");
    assert!(srv.contains("flush"), "{lines:#?}");
    assert!(!srv.contains(" ans "), "{lines:#?}");
    assert_eq!(col(srv, "192.168.1."), col(h, "SOURCE"), "{lines:#?}");
}

#[test]
fn sect_shows_exactly_when_every_column_fits() {
    let app = app_with_sections(
        browse::RecordSection::Answer,
        browse::RecordSection::Additional,
    );
    // TYPE 8, TTL 12, FLUSH 6, SECT 4, RDATA min 20, five gaps, and
    // SOURCE sized to `192.168.1.2:5353`.
    let need = 8 + 12 + 6 + 4 + 20 + 5 + "192.168.1.2:5353".len() as u16;
    let (mut below, mut at_or_above) = (false, false);
    for width in 60..=200 {
        let (h, inner) = header_at(&app, width);
        assert_eq!(h.contains("SECT"), inner >= need, "width {width}: {h}");
        below |= inner < need;
        at_or_above |= inner >= need;
    }
    assert!(below && at_or_above, "scan crosses the threshold");
}
