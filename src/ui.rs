// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use std::io;
use std::io::IsTerminal;
use std::net::SocketAddr;

use crossterm::event::{DisableMouseCapture, EnableMouseCapture};
use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, BorderType, Borders, Cell, Clear, HighlightSpacing, List, ListItem, ListState,
    Paragraph, Row, Table, TableState, Wrap,
};
use ratatui::Frame;

use crate::anomalies::Anomaly;
use crate::app::{App, DisplayItem, DragMode, Focus};
use crate::devices::{AddressBook, DeviceName};
use std::collections::HashSet;

mod diagnostics;
mod hex;
mod questions;
mod records;
mod services;
use diagnostics::*;
use hex::*;
use questions::*;
use records::*;
use services::*;

pub type Terminal = ratatui::Terminal<CrosstermBackend<io::Stdout>>;

pub fn try_init() -> io::Result<Option<Terminal>> {
    if !io::stdin().is_terminal() {
        return Ok(None);
    }
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen, EnableMouseCapture)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).map(Some)
}

pub fn try_restore(initialized: bool) -> io::Result<()> {
    if !initialized {
        return Ok(());
    }
    disable_raw_mode()?;
    execute!(io::stdout(), DisableMouseCapture)?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

/// kill target for suspend: suspend_pid() applied to the live ids.
#[cfg(unix)]
fn suspend_target() -> nix::unistd::Pid {
    use nix::unistd::{getpgrp, getsid};
    suspend_pid(getpgrp(), getsid(None).ok())
}

/// Decide the kill target from the own process group and session id. A
/// negative pid addresses a group for kill(2): stopping the whole job
/// also suspends wrappers such as `sh -c 'mex; ...'`, so the shell gets
/// its prompt back and `fg` resumes everything. No job-control separation
/// (our group is the session leader's own group) means the interactive
/// shell shares it: stopping the group would freeze the shell with nobody
/// left to `fg`, so stop just ourselves instead (as does an unknown
/// session, where safety wins over wrapper coverage).
#[cfg(unix)]
fn suspend_pid(group: nix::unistd::Pid, session: Option<nix::unistd::Pid>) -> nix::unistd::Pid {
    use nix::unistd::Pid;
    match session {
        Some(sid) if group != sid => Pid::from_raw(-group.as_raw()),
        _ => Pid::this(),
    }
}

/// Leave the terminal, suspend the process, and re-enter on resume:
/// Ctrl+Z arrives as a key event (raw mode disables ISIG), so the event
/// loop calls this instead of relying on SIGTSTP. Returns false when the
/// terminal is gone and the app should exit instead. Unix only.
#[cfg(unix)]
pub fn suspend(term: &mut Terminal) -> io::Result<bool> {
    // The draw loop hides the cursor and never shows it (mex sets no cursor
    // position), so reveal it explicitly: the surviving shell needs a cursor
    // while we're stopped. Ratatui hides it again on the next draw, and its
    // Drop handler stays consistent via the tracked flag.
    let _ = term.show_cursor();
    try_restore(true)?;
    // Stop the whole foreground job (see suspend_target), not just
    // ourselves. Use SIGSTOP, which cannot be caught, ignored, or blocked.
    let stopped = nix::sys::signal::kill(suspend_target(), nix::sys::signal::Signal::SIGSTOP);
    // Execution resumes here after `fg` (or immediately if SIGSTOP failed).
    if let Err(e) = stopped {
        eprintln!("mex: failed to suspend: {e}");
    }
    let Some(restored) = try_init()? else {
        return Ok(false);
    };
    *term = restored;
    // Ratatui diffs frames: clear so the resumed screen repaints fully.
    term.clear()?;
    Ok(true)
}

pub fn draw(frame: &mut Frame, app: &App) {
    // The analyzer is the costliest derived view; run it once per frame
    // and share the result with every pane that marks findings.
    draw_with_findings(frame, app, &app.anomalies());
}

/// One frame from a given finding set (tests inject crafted findings).
pub(crate) fn draw_with_findings(frame: &mut Frame, app: &App, found: &[Anomaly]) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(frame.area());

    draw_header(frame, chunks[0], app);
    draw_body(frame, chunks[1], app, found);
    if app.view_state().show_diagnostics {
        draw_diagnostics_overlay(frame, app, found);
    }
    if let Some(text) = app.status_popup() {
        draw_status_popup(frame, text);
    }
}

fn draw_header(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let uptime = chrono::Duration::from_std(app.start_time().elapsed()).unwrap_or_default();
    let uptime_str = format!(
        "{:02}:{:02}:{:02}",
        uptime.num_hours(),
        uptime.num_minutes() % 60,
        uptime.num_seconds() % 60
    );

    let line = Line::from(vec![
        Span::styled(
            " mex ",
            Style::default()
                .add_modifier(Modifier::BOLD)
                .fg(Color::Cyan),
        ),
        Span::raw(format!(
            "│ {} pkts │ {} svcs │ uptime {}{}  [q] quit [tab] pane [j/k] move [enter] fold [*] all [d] diagnostics{}",
            app.packet_count(),
            app.services().len(),
            uptime_str,
            if app.is_passive() { " │ passive" } else { "" },
            // `r` acts only on a `self` question in the Questions pane
            // (#394): hint it only there.
            if app.view_state().focus == Focus::Questions
                && matches!(
                    app.selected_detail_entry(),
                    Some(crate::app::DetailEntry::Question { source, .. })
                        if *source == crate::app::SELF_SOURCE
                )
            {
                " [r] send"
            } else {
                ""
            },
        )),
    ]);

    let header = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Gray)),
    );
    frame.render_widget(header, area);
}

fn draw_body(frame: &mut Frame, area: ratatui::layout::Rect, app: &App, found: &[Anomaly]) {
    app.layout().body_rect.set(area);
    // No gutter: the abutting pane borders are the drag handles, so no
    // space is lost to divider widgets.
    let left = app.view_state().left_pct.clamp(15, 80);
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(left), Constraint::Min(0)])
        .split(area);

    app.layout().left_rect.set(chunks[0]);
    app.layout().right_rect.set(chunks[1]);
    draw_service_list(frame, chunks[0], app, found);
    draw_detail_panel(frame, chunks[1], app, found);
}

/// Centered popup rect covering `pct_x`/`pct_y` percent of `area`.
fn centered_rect(pct_x: u16, pct_y: u16, area: Rect) -> Rect {
    let popup_w = area.width.saturating_mul(pct_x) / 100;
    let popup_h = area.height.saturating_mul(pct_y) / 100;
    let w = if area.width <= 20 {
        area.width.max(1)
    } else {
        popup_w.clamp(20, area.width).max(1)
    };
    let h = if area.height <= 10 {
        area.height.max(1)
    } else {
        popup_h.clamp(10, area.height).max(1)
    };
    let x = area.x + area.width.saturating_sub(w) / 2;
    let y = area.y + area.height.saturating_sub(h) / 2;
    Rect {
        x,
        y,
        width: w,
        height: h,
    }
}

/// Clamp a scroll offset to the valid range. Pure helper, unit-tested.
fn clamp_scroll(offset: usize, total: usize, viewport: usize) -> usize {
    if viewport == 0 || total <= viewport {
        return 0;
    }
    offset.min(total - viewport)
}

/// Severity color shared by markers, badges and finding rows.
fn severity_color(s: crate::anomalies::Severity) -> Color {
    match s {
        crate::anomalies::Severity::Error => Color::Red,
        crate::anomalies::Severity::Warning => Color::Yellow,
        crate::anomalies::Severity::Info => Color::Blue,
    }
}

/// Count and worst severity of a finding set, `None` when empty.
fn worst_of<'a>(
    findings: impl IntoIterator<Item = &'a Anomaly>,
) -> Option<(usize, crate::anomalies::Severity)> {
    findings.into_iter().fold(None, |acc, a| match acc {
        None => Some((1, a.severity)),
        Some((n, s)) if a.severity.rank() > s.rank() => Some((n + 1, a.severity)),
        Some((n, s)) => Some((n + 1, s)),
    })
}

/// Level icon span, severity-colored.
fn level_icon(s: crate::anomalies::Severity) -> Span<'static> {
    Span::styled(
        App::anomaly_level_icon(s).to_string(),
        Style::default().fg(severity_color(s)),
    )
}

/// ` [<worst icon> N]` Hosts-pane badge (#248), nothing for no findings.
fn badge_spans(count: Option<&(usize, crate::anomalies::Severity)>) -> Vec<Span<'static>> {
    match count {
        Some(&(n, s)) if n > 0 => vec![Span::raw(" ["), level_icon(s), Span::raw(format!(" {n}]"))],
        _ => Vec::new(),
    }
}

/// ` · <worst icon> N` pane-title suffix for the findings a pane shows.
fn title_count_spans(count: Option<(usize, crate::anomalies::Severity)>) -> Vec<Span<'static>> {
    match count {
        Some((n, s)) => vec![Span::raw("· "), level_icon(s), Span::raw(format!(" {n} "))],
        None => Vec::new(),
    }
}

/// Data cell of a finding child row:
/// `<kind>[ <scope>]: <message> (<rfc>[, <requirement>])`.
fn finding_text(
    a: &Anomaly,
    identity_count: &std::collections::HashMap<(String, u16), usize>,
) -> Line<'static> {
    let scope = crate::anomalies::visible_scope(a, identity_count);
    let head = if scope.is_empty() {
        a.kind.as_str().to_string()
    } else {
        format!("{} {scope}", a.kind.as_str())
    };
    Line::from(vec![
        Span::styled(
            format!("{head}: {}", a.message),
            Style::default().fg(Color::White),
        ),
        Span::styled(
            if a.requirement.is_empty() {
                format!(" ({})", a.rfc)
            } else {
                format!(" ({}, {})", a.rfc, a.requirement)
            },
            Style::default().fg(Color::Gray),
        ),
    ])
}

/// Where finding rows of one table may draw: the table's columns as
/// laid out (x and width inside the borders) and the most lines a
/// single finding may take (the viewport height).
pub(super) struct FindingFit {
    cols: Vec<Rect>,
    max_lines: usize,
}

impl FindingFit {
    /// Columns of a bordered table drawn in `area` with `widths`, laid
    /// out the way ratatui's `Table` does (start flex, one-cell
    /// spacing, no highlight symbol).
    pub(super) fn new(area: Rect, widths: &[Constraint], max_lines: usize) -> Self {
        let inner = Rect::new(0, 0, area.width.saturating_sub(2), 1);
        let cols = Layout::horizontal(widths.iter().copied())
            .flex(ratatui::layout::Flex::Start)
            .spacing(1)
            .split(inner)
            .to_vec();
        Self { cols, max_lines }
    }

    /// Cells from the start of column `from` to the end of column `to`.
    fn span(&self, from: usize, to: usize) -> usize {
        self.cols
            .get(from)
            .zip(self.cols.get(to))
            .map_or(0, |(a, b)| b.right().saturating_sub(a.x) as usize)
    }
}

/// One grapheme with its style: the unit ratatui draws, so wrapping
/// measures and breaks exactly where rendering does.
type Glyph<'a> = (&'a str, Style);

/// The styled graphemes of `spans`, in order.
fn glyphs<'a>(spans: &'a [Span<'a>]) -> impl Iterator<Item = Glyph<'a>> {
    spans
        .iter()
        .flat_map(|s| s.styled_graphemes(Style::default()))
        .map(|g| (g.symbol, g.style))
}

/// Display width of one grapheme in terminal cells, as ratatui draws it.
fn glyph_width(g: &str) -> usize {
    Span::raw(g).width()
}

/// Word-wrap styled spans to `width` cells (#410): breaks at spaces
/// (runs of spaces collapse, none starts a line), breaks words wider
/// than the line between graphemes, and keeps every grapheme's style.
/// Text that fits is returned as is. At least one line.
fn wrap_spans(spans: &[Span<'_>], width: usize) -> Vec<Line<'static>> {
    /// A word's graphemes, each with its style.
    type Word<'a> = Vec<Glyph<'a>>;
    let width = width.max(1);
    // Text that fits stays exactly as it is, spaces included.
    if spans.iter().map(Span::width).sum::<usize>() <= width {
        return vec![Line::from(
            spans
                .iter()
                .map(|s| Span::styled(s.content.to_string(), s.style))
                .collect::<Vec<_>>(),
        )];
    }
    // Words, each with the style of the space before it.
    let mut words: Vec<(Option<Style>, Word)> = Vec::new();
    let mut sep = None;
    let mut word: Word = Vec::new();
    for (g, style) in glyphs(spans) {
        if g == " " {
            if !word.is_empty() {
                words.push((sep.take(), std::mem::take(&mut word)));
            }
            sep.get_or_insert(style);
        } else {
            word.push((g, style));
        }
    }
    if !word.is_empty() {
        words.push((sep.take(), word));
    }

    let mut lines: Vec<Word> = Vec::new();
    let mut cur: Word = Vec::new();
    let mut used = 0;
    for (sep, word) in words {
        let w: usize = word.iter().map(|(g, _)| glyph_width(g)).sum();
        if !cur.is_empty() {
            if used + 1 + w <= width {
                cur.push((" ", sep.unwrap_or_default()));
                cur.extend(word);
                used += 1 + w;
                continue;
            }
            lines.push(std::mem::take(&mut cur));
            used = 0;
        }
        for (g, style) in word {
            let gw = glyph_width(g);
            if used > 0 && used + gw > width {
                lines.push(std::mem::take(&mut cur));
                used = 0;
            }
            cur.push((g, style));
            used += gw;
        }
    }
    // The last line: never empty unless there were no words at all.
    lines.push(cur);
    lines.into_iter().map(styled_line).collect()
}

/// One line from styled graphemes, runs of one style merged into a span.
fn styled_line(glyphs: Vec<Glyph<'_>>) -> Line<'static> {
    let mut spans: Vec<Span<'static>> = Vec::new();
    let mut run = String::new();
    let mut run_style: Option<Style> = None;
    for (g, style) in glyphs {
        match run_style {
            Some(s) if s != style => spans.push(Span::styled(std::mem::take(&mut run), s)),
            _ => {}
        }
        run_style = Some(style);
        run.push_str(g);
    }
    if let Some(style) = run_style {
        spans.push(Span::styled(run, style));
    }
    Line::from(spans)
}

/// The finding text wrapped to `width`, at most `max_lines` lines; a cut
/// finding ends in `…` so the clip shows.
fn finding_lines(
    a: &Anomaly,
    identity_count: &std::collections::HashMap<(String, u16), usize>,
    width: usize,
    max_lines: usize,
) -> Vec<Line<'static>> {
    let text = finding_text(a, identity_count);
    let mut lines = wrap_spans(&text.spans, width);
    let max_lines = max_lines.max(1);
    if lines.len() > max_lines {
        lines.truncate(max_lines);
        // Keep the whole graphemes that leave a cell for `…`.
        let last = lines.pop().unwrap_or_default();
        let style = glyphs(&last.spans)
            .last()
            .map(|(_, s)| s)
            .unwrap_or_default();
        let room = width.max(1) - 1;
        let mut used = 0;
        let mut kept: Vec<Glyph<'_>> = glyphs(&last.spans)
            .take_while(|(g, _)| {
                used += glyph_width(g);
                used <= room
            })
            .collect();
        kept.push(("…", style));
        let cut = styled_line(kept);
        lines.push(cut);
    }
    lines
}

/// Child row for one finding: icon in the type column, the announcer or
/// querier in the source column, the finding text in the data column,
/// wrapped to the width it spans (#410). Returns the row and its height.
fn finding_row(
    a: &Anomaly,
    identity_count: &std::collections::HashMap<(String, u16), usize>,
    book: &AddressBook,
    source_col: usize,
    data_col: usize,
    under_parent: bool,
    fit: &FindingFit,
) -> (Row<'static>, u16) {
    let text = |from: usize| {
        let lines = finding_lines(a, identity_count, fit.span(from, data_col), fit.max_lines);
        let height = lines.len() as u16;
        (ratatui::text::Text::from(lines), height)
    };
    if under_parent {
        // Under its record or question (#266): the parent row already
        // shows the source and carries the severity mark, so the text
        // alone runs from the second column to the end.
        let (body, height) = text(1);
        let row = Row::new(vec![
            Cell::from(""),
            Cell::from(body).column_span(data_col as u16),
        ]);
        return (row.height(height), height);
    }
    let mut cells: Vec<Cell<'static>> = (0..=data_col).map(|_| Cell::from("")).collect();
    cells[0] = Cell::from(Line::from(vec![Span::raw("  "), level_icon(a.severity)]));
    let Some(src) = a.source.as_deref() else {
        // Unsourced findings (e.g. `conflicting-answers`, whose message
        // names every responder) take the empty source column too, so
        // their long text isn't clipped to the data column.
        let (body, height) = text(source_col);
        cells.truncate(source_col);
        cells.push(Cell::from(body).column_span((data_col - source_col + 1) as u16));
        return (Row::new(cells).height(height), height);
    };
    // No parent row names the responder here (`service` / `host`
    // blocks, `(unattributed)`): name it, device included (#246).
    let source = named(src.to_string(), book.resolve_label(src));
    let (body, height) = text(data_col);
    cells[source_col] = Cell::from(source).style(Style::default().fg(Color::Gray));
    cells[data_col] = Cell::from(body);
    (Row::new(cells).height(height), height)
}

/// `label (Name)`, or the label alone when no device is named (#246).
fn named(label: String, device: Option<DeviceName>) -> String {
    match device {
        Some(d) => format!("{label} ({})", d.display()),
        None => label,
    }
}

/// Source cell of a record row: the device name only when it is not the
/// displayed service's own host, so proxies and foreign responders stand
/// out while ordinary rows stay uncluttered.
fn record_source_label(
    rec: &crate::browse::RawRecord,
    book: &AddressBook,
    own: &HashSet<String>,
) -> String {
    let device = book
        .resolve(rec.source.ip())
        .filter(|d| !own.contains(&d.host_id()));
    named(source_label(rec), device)
}

/// A cell's text with the worst finding's icon appended, if any.
fn marked_cell(
    text: String,
    mark: Option<crate::anomalies::Severity>,
    style: Style,
) -> Cell<'static> {
    match mark {
        Some(s) => Cell::from(Line::from(vec![
            Span::styled(text, style),
            Span::raw(" "),
            level_icon(s),
        ])),
        None => Cell::from(Span::styled(text, style)),
    }
}

/// Transient confirmation popup (state dump result): centered, 3 rows,
/// auto-expires after 3s and dismissed by any key (see `App::status_popup`).
fn draw_status_popup(frame: &mut Frame, text: String) {
    let area = frame.area();
    let width = (text.len() + 6)
        .min(area.width.saturating_sub(4) as usize)
        .max(1) as u16;
    let popup = Rect {
        x: area.x + area.width.saturating_sub(width) / 2,
        y: area.y + area.height.saturating_sub(3) / 2,
        width,
        height: 3.min(area.height).max(1),
    };
    frame.render_widget(Clear, popup);
    let para = Paragraph::new(text)
        .alignment(Alignment::Center)
        .wrap(Wrap { trim: true })
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_style(Style::default().fg(Color::Green)),
        );
    frame.render_widget(para, popup);
}

fn draw_detail_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &App, found: &[Anomaly]) {
    // Right side: Answers table (with its findings inline) on top, its
    // questions below with their own captions (age, not TTL), hex dump of
    // the selected entry at the bottom. The abutting pane borders are the
    // drag handles.
    let answers = app.view_state().answers_pct.clamp(10, 70);
    let questions = app
        .view_state()
        .questions_pct
        .clamp(10, 70)
        .min(90u16.saturating_sub(answers));
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage(answers),
            Constraint::Percentage(questions),
            Constraint::Min(0),
        ])
        .split(area);

    app.layout().answers_rect.set(panes[0]);
    app.layout().questions_rect.set(panes[1]);
    app.layout().hex_rect.set(panes[2]);
    draw_records_tab(frame, panes[0], app, found);
    draw_questions_tab(frame, panes[1], app, found);
    draw_hex_tab(frame, panes[2], app);
}

/// Focused panes get heavy box-drawing borders so the active pane stands out
/// at a glance; unfocused panes keep the light default. The border still
/// occupies a single cell, so no layout space is lost to the emphasis.
fn pane_border_type(focused: bool) -> BorderType {
    if focused {
        BorderType::Thick
    } else {
        BorderType::Plain
    }
}

/// Border color: resize hover/drag wins (subtle cyan seam) over focus white.
fn border_color(focused: bool, resizing: bool) -> Style {
    Style::default().fg(if resizing {
        Color::Cyan
    } else if focused {
        Color::White
    } else {
        Color::Gray
    })
}

fn resize_active(app: &App, mode: DragMode) -> bool {
    // Never glow behind the diagnostics overlay: it owns all input while open.
    !app.view_state().show_diagnostics
        && (app.view_state().drag == mode || app.view_state().hover.get() == mode)
}

/// Source cell for the Records table (`RawRecord::source_label`).
fn source_label(rec: &crate::browse::RawRecord) -> String {
    rec.source_label()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn test_record(iface: &str) -> crate::browse::RawRecord {
        crate::browse::RawRecord {
            name: "_http._tcp.local.".to_string(),
            owner_labels: vec![b"_http".to_vec(), b"_tcp".to_vec(), b"local".to_vec()],
            ptr_target_labels: Some(vec![
                b"Test".to_vec(),
                b"_http".to_vec(),
                b"_tcp".to_vec(),
                b"local".to_vec(),
            ]),
            rtype: 12,
            rtype_str: "PTR".to_string(),
            flush_bit: false,
            qu: false,
            invalid_utf8: false,
            ttl: 120,
            rdata: "Test._http._tcp.local.".to_string(),
            wire: Vec::new(),
            source: "192.168.1.5:5353".parse().unwrap(),
            iface: iface.to_string(),
            ifindex: 0,
            dst_is_multicast: true,
            section: crate::browse::RecordSection::Answer,
            received_at: Instant::now(),
            trigger: None,
        }
    }

    #[test]
    fn source_label_shows_interface_when_known() {
        assert_eq!(source_label(&test_record("br0")), "192.168.1.5:5353@br0");
        assert_eq!(source_label(&test_record("")), "192.168.1.5:5353");
    }

    #[test]
    fn source_label_uses_zone_notation_only_for_v6_link_local() {
        let mut rec = test_record("eth0");
        rec.source = "[fe80::1]:5353".parse().unwrap();
        assert_eq!(source_label(&rec), "[fe80::1]:5353%eth0");
        rec.source = "[2001:db8::1]:5353".parse().unwrap();
        assert_eq!(source_label(&rec), "[2001:db8::1]:5353@eth0");
    }

    #[test]
    fn source_label_omits_interface_when_zone_present() {
        let mut rec = test_record("eth0");
        rec.source = "[fe80::1%2]:5353".parse().unwrap();
        assert_eq!(source_label(&rec), "[fe80::1%2]:5353");
    }

    #[test]
    fn question_source_label_marks_self() {
        assert_eq!(
            question_source_label(&crate::app::SELF_SOURCE, &AddressBook::new(HashSet::new())),
            "self"
        );
        let addr: SocketAddr = "192.168.1.5:5353".parse().unwrap();
        assert_eq!(
            question_source_label(&addr, &AddressBook::new(HashSet::new())),
            "192.168.1.5:5353"
        );
        // Ephemeral source ports (§5.1) mark one-shot resolvers; other
        // ports render bare.
        let stub: SocketAddr = "192.168.1.5:45678".parse().unwrap();
        assert_eq!(
            question_source_label(&stub, &AddressBook::new(HashSet::new())),
            "192.168.1.5:45678 (one-shot)"
        );
        let dns: SocketAddr = "192.168.1.5:53".parse().unwrap();
        assert_eq!(
            question_source_label(&dns, &AddressBook::new(HashSet::new())),
            "192.168.1.5:53"
        );
    }

    #[cfg(unix)]
    #[test]
    fn suspend_targets_foreground_process_group_not_just_self() {
        use nix::unistd::Pid;
        assert_eq!(
            suspend_pid(Pid::from_raw(100), Some(Pid::from_raw(50))),
            Pid::from_raw(-100)
        );
    }

    #[cfg(unix)]
    #[test]
    fn suspend_falls_back_to_self_in_session_leaders_group() {
        use nix::unistd::Pid;
        // No job-control separation: the interactive shell shares our
        // group, so stopping it would freeze the shell. Unknown session:
        // same safe fallback.
        assert_eq!(
            suspend_pid(Pid::from_raw(50), Some(Pid::from_raw(50))),
            Pid::this()
        );
        assert_eq!(suspend_pid(Pid::from_raw(100), None), Pid::this());
    }

    #[test]
    fn ttl_cell_color_marks_expiry_fraction() {
        // Aligned to the §5.2 requery schedule: yellow inside the
        // 80-95% refresh window, red past the final ~95% refresh.
        // Expired without a goodbye stays red: the responder went silent.
        assert_eq!(ttl_cell_color(0, 120), Some(Color::Red));
        // A goodbye (TTL 0) is a clean withdrawal, dimmed rather than red.
        assert_eq!(ttl_cell_color(0, 0), Some(Color::DarkGray));
        assert_eq!(ttl_cell_color(10, 0), Some(Color::DarkGray));
        // ttl=120: yellow at rem <= 24 (elapsed >= 80%), red at rem <= 6.
        assert_eq!(ttl_cell_color(25, 120), None);
        assert_eq!(ttl_cell_color(24, 120), Some(Color::Yellow));
        assert_eq!(ttl_cell_color(23, 120), Some(Color::Yellow));
        assert_eq!(ttl_cell_color(7, 120), Some(Color::Yellow));
        assert_eq!(ttl_cell_color(6, 120), Some(Color::Red));
        assert_eq!(ttl_cell_color(60, 120), None);
        assert_eq!(ttl_cell_color(120, 120), None);
        // Clock skew (remaining beyond original) counts as healthy.
        assert_eq!(ttl_cell_color(200, 120), None);
    }

    #[test]
    fn fit_row_extent_pulls_children_into_view() {
        let one = [1; 20];
        // Parent at 8 with 3 children (extent end 12), viewport 10: the
        // old offset 0 clips the children, so scroll to 2.
        assert_eq!(fit_row_extent(0, 8, 8, 12, 10, &one), 2);
        // Already visible: offset untouched.
        assert_eq!(fit_row_extent(2, 8, 8, 12, 10, &one), 2);
        // No children (extent is the row itself): no scroll.
        assert_eq!(fit_row_extent(0, 3, 3, 4, 10, &one), 0);
    }

    #[test]
    fn fit_row_extent_pins_oversized_expansion_to_parent() {
        // 10 children in a viewport of 5: cannot fit, so pin the parent
        // (row 8) to the top; the rest pages via Ctrl-j/k.
        assert_eq!(fit_row_extent(0, 8, 8, 19, 5, &[1; 30]), 8);
    }

    /// Plain text of each line.
    fn texts(lines: &[Line<'_>]) -> Vec<String> {
        lines.iter().map(|l| l.to_string()).collect()
    }

    #[test]
    fn wrap_spans_breaks_at_spaces_and_fits_exactly() {
        let spans = [Span::raw("ab cd  ef")];
        assert_eq!(texts(&wrap_spans(&spans, 5)), ["ab cd", "ef"]);
        assert_eq!(texts(&wrap_spans(&spans, 4)), ["ab", "cd", "ef"]);
        // Fitting text is left alone, double space included.
        assert_eq!(texts(&wrap_spans(&spans, 20)), ["ab cd  ef"]);
        assert_eq!(texts(&wrap_spans(&spans, 9)), ["ab cd  ef"]);
        assert_eq!(texts(&wrap_spans(&[], 5)), [""]);
        // Trailing spaces end no line; only spaces wrap to one empty line.
        assert_eq!(texts(&wrap_spans(&[Span::raw("ab cd  ")], 3)), ["ab", "cd"]);
        assert_eq!(texts(&wrap_spans(&[Span::raw("      ")], 3)), [""]);
    }

    #[test]
    fn wrap_spans_breaks_long_words_and_survives_tiny_widths() {
        let spans = [Span::raw("abcdefg h")];
        assert_eq!(texts(&wrap_spans(&spans, 3)), ["abc", "def", "g h"]);
        assert_eq!(texts(&wrap_spans(&spans, 0)).len(), 8);
        assert_eq!(texts(&wrap_spans(&spans, 1)).len(), 8);
    }

    #[test]
    fn wrap_spans_measures_wide_chars_by_cells() {
        // `日` takes two cells: three fit in six, not in five.
        let spans = [Span::raw("日日日")];
        assert_eq!(texts(&wrap_spans(&spans, 6)), ["日日日"]);
        assert_eq!(texts(&wrap_spans(&spans, 5)), ["日日", "日"]);
    }

    #[test]
    fn wrap_spans_measures_and_keeps_whole_graphemes() {
        // `❤️` is `❤` plus a variation selector: two cells as drawn,
        // though its chars measure one. `b` must move to the next line.
        let lines = wrap_spans(&[Span::raw("a❤️b")], 3);
        assert_eq!(texts(&lines), ["a❤️", "b"]);
        assert!(lines.iter().all(|l| l.width() <= 3));
        // A ZWJ family is one grapheme: never split.
        let family = "👩\u{200d}👩\u{200d}👧";
        let lines = wrap_spans(&[Span::raw(format!("ab{family}"))], 3);
        assert_eq!(texts(&lines), ["ab".to_string(), family.to_string()]);
    }

    #[test]
    fn wrap_spans_keeps_styles_across_breaks() {
        let white = Style::default().fg(Color::White);
        let gray = Style::default().fg(Color::Gray);
        let spans = [
            Span::styled("kind: msg", white),
            Span::styled(" (RFC 1)", gray),
        ];
        let lines = wrap_spans(&spans, 9);
        assert_eq!(texts(&lines), ["kind: msg", "(RFC 1)"]);
        assert_eq!(lines[0].spans, [Span::styled("kind: msg", white)]);
        assert_eq!(lines[1].spans, [Span::styled("(RFC 1)", gray)]);
        // On one line the separator keeps the suffix's style.
        let one = wrap_spans(&spans, 40);
        assert_eq!(
            one[0].spans,
            [
                Span::styled("kind: msg", white),
                Span::styled(" (RFC 1)", gray)
            ]
        );
    }

    #[test]
    fn fit_row_extent_counts_wrapped_rows_in_lines() {
        // Parent at 5 with one 4-line finding (#410), viewport 8: rows
        // 0..=4 plus 5 lines of extent need 10, so scroll by 2 rows.
        let mut heights = [1; 10];
        heights[6] = 4;
        assert_eq!(fit_row_extent(0, 5, 5, 7, 8, &heights), 2);
        // Exactly fits from row 3: lines 3..7 are 2 + 1 + 4 = 7 ≤ 8.
        assert_eq!(fit_row_extent(3, 5, 5, 7, 8, &heights), 3);
        // Taller than the viewport: pin the parent.
        heights[6] = 9;
        assert_eq!(fit_row_extent(0, 5, 5, 7, 8, &heights), 5);
        // The bottom never scrolls past the last row's end: rows 4..10
        // take 1+1+4+1+1+1 = 9 > 8, so the lowest offset is 5.
        heights[6] = 4;
        assert_eq!(fit_row_extent(9, 9, 9, 10, 8, &heights), 5);
    }

    #[test]
    fn fit_row_extent_reveals_leading_rows_of_the_first_record() {
        // First record at row 4 under four header rows, scrolled to the
        // bottom (offset 20): all of [0, 5) fits, so show from row 0.
        assert_eq!(fit_row_extent(20, 0, 4, 5, 10, &[1; 30]), 0);
        // Its two children (extent end 7) fit with the headers too.
        assert_eq!(fit_row_extent(20, 0, 4, 7, 10, &[1; 30]), 0);
    }

    #[test]
    fn fit_row_extent_keeps_the_first_record_when_headers_overflow() {
        // Six header rows over a viewport of 3: scroll up only as far as
        // keeps the record (row 6) on the last visible row.
        assert_eq!(fit_row_extent(20, 0, 6, 7, 3, &[1; 30]), 4);
        // Children that need the room still win over the headers.
        assert_eq!(fit_row_extent(20, 0, 6, 9, 3, &[1; 30]), 6);
    }

    #[test]
    fn centered_rect_covers_most_of_area() {
        let area = Rect::new(0, 0, 100, 40);
        let popup = centered_rect(80, 85, area);
        assert_eq!((popup.width, popup.height), (80, 34));
        assert_eq!((popup.x, popup.y), (10, 3));
    }

    #[test]
    fn centered_rect_clamps_to_tiny_terminals() {
        let area = Rect::new(0, 0, 10, 6);
        let popup = centered_rect(80, 85, area);
        assert!(popup.width <= area.width);
        assert!(popup.height <= area.height);
        assert!(popup.width >= 1 && popup.height >= 1);
    }

    #[test]
    fn clamp_scroll_pins_to_valid_range() {
        assert_eq!(clamp_scroll(0, 50, 10), 0);
        assert_eq!(clamp_scroll(5, 50, 10), 5);
        assert_eq!(clamp_scroll(100, 50, 10), 40);
        assert_eq!(clamp_scroll(7, 5, 10), 0);
        assert_eq!(clamp_scroll(3, 50, 0), 0);
    }

    #[test]
    fn focused_pane_gets_thick_border() {
        assert_eq!(pane_border_type(true), BorderType::Thick);
        assert_eq!(pane_border_type(false), BorderType::Plain);
    }

    #[test]
    fn shift_str_pans_by_chars() {
        assert_eq!(shift_str("hello", 0), "hello");
        assert_eq!(shift_str("hello", 2), "llo");
        assert_eq!(shift_str("hello", 5), "");
        assert_eq!(shift_str("hello", 99), "");
        // Level icons are single chars, not bytes: skipping one reveals
        // the text behind the icon.
        assert_eq!(
            shift_str("\u{f057} missing-addr", 0),
            "\u{f057} missing-addr"
        );
        assert_eq!(shift_str("\u{f057} missing-addr", 1), " missing-addr");
        assert_eq!(shift_str("\u{f057} missing-addr", 2), "missing-addr");
    }
}
