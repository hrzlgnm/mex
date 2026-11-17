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
    Block, Borders, Cell, Clear, HighlightSpacing, List, ListItem, ListState, Paragraph, Row,
    Table, TableState, Wrap,
};
use ratatui::Frame;

use crate::anomalies::Anomaly;
use crate::app::{App, DisplayItem, DragMode, Focus};
use crate::devices::{AddressBook, DeviceName};
use std::collections::HashSet;

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
    if app.show_metrics {
        draw_metrics_overlay(frame, app, found);
    }
    if let Some(text) = app.status_popup() {
        draw_status_popup(frame, text);
    }
}

fn draw_header(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let uptime = chrono::Duration::from_std(app.start_time.elapsed()).unwrap_or_default();
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
            "│ {} pkts │ {} svcs │ uptime {}{}  [q] quit [tab] pane [j/k] move [enter] fold [*] all [m] metrics",
            app.packet_count,
            app.services.len(),
            uptime_str,
            if app.passive { " │ passive" } else { "" },
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
    app.body_rect.set(area);
    // No gutter: the abutting pane borders are the drag handles, so no
    // space is lost to divider widgets.
    let left = app.left_pct.clamp(15, 80);
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Percentage(left), Constraint::Min(0)])
        .split(area);

    app.left_rect.set(chunks[0]);
    app.right_rect.set(chunks[1]);
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

fn draw_metrics_overlay(frame: &mut Frame, app: &App, found: &[Anomaly]) {
    let area = centered_rect(80, 85, frame.area());
    frame.render_widget(Clear, area);

    let rows = app.metrics_rows_in(found);
    let total = rows.len();
    let viewport = (area.height as usize).saturating_sub(4);
    app.metrics_viewport.set(viewport);
    let offset = clamp_scroll(app.metrics_scroll.get(), total, viewport);
    app.metrics_scroll.set(offset);

    // Compact key column: size to the longest key (single-space indent
    // plus one cell of padding) instead of a fixed 38% split, so values
    // start further left. Capped so one pathological key cannot eat the
    // popup, and to the popup width on tiny terminals.
    let key_cap = area.width.saturating_sub(12).clamp(10, 32) as usize;
    let key_w = rows
        .iter()
        .filter(|(_, v)| !v.is_empty())
        .map(|(k, _)| k.chars().count() + 2)
        .max()
        .unwrap_or(10)
        .clamp(10, 32)
        .min(key_cap) as u16;

    // Horizontal pan: the key column stays frozen while values shift left
    // by `hscroll` chars. Clamp against the longest value minus the
    // visible value width so panning stops at the end of the text.
    let value_w = (area.width as usize).saturating_sub(key_w as usize + 5);
    let longest = rows
        .iter()
        .map(|(_, v)| v.chars().count())
        .max()
        .unwrap_or(0);
    let hscroll = app
        .metrics_hscroll
        .get()
        .min(longest.saturating_sub(value_w.max(1)));
    app.metrics_hscroll.set(hscroll);

    let section_style = Style::default()
        .add_modifier(Modifier::BOLD)
        .fg(Color::Cyan);
    let key_style = Style::default().fg(Color::Gray);
    let val_style = Style::default().fg(Color::White);

    let body: Vec<Row<'_>> = rows
        .into_iter()
        .map(|(k, v)| {
            if v.is_empty() {
                Row::new(vec![Cell::from(k).style(section_style), Cell::from("")])
            } else {
                Row::new(vec![
                    Cell::from(format!(" {k}")).style(key_style),
                    Cell::from(shift_str(&v, hscroll)).style(val_style),
                ])
            }
        })
        .collect();

    let widths = [Constraint::Length(key_w), Constraint::Min(0)];
    let table = Table::new(body, widths)
        .header(
            Row::new(vec!["METRIC", "VALUE"]).style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Metrics (m/Esc close · j/k ↕ · h/l ↔) ")
                .border_style(Style::default().fg(Color::White)),
        );

    let mut state = TableState::default();
    *state.offset_mut() = offset;
    frame.render_stateful_widget(table, area, &mut state);
    app.metrics_scroll.set(state.offset());
}

/// Skip `skip` chars of `s` for horizontal panning. Char-boundary safe;
/// the table truncates the tail to the visible width itself.
fn shift_str(s: &str, skip: usize) -> String {
    if skip == 0 {
        return s.to_string();
    }
    s.chars().skip(skip).collect()
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

/// Child row for one finding: icon in the type column, the announcer or
/// querier in the source column, the finding text in the data column.
fn finding_row(
    a: &Anomaly,
    identity_count: &std::collections::HashMap<(String, u16), usize>,
    book: &AddressBook,
    source_col: usize,
    data_col: usize,
) -> Row<'static> {
    let mut cells: Vec<Cell<'static>> = (0..=data_col).map(|_| Cell::from("")).collect();
    cells[0] = Cell::from(Line::from(vec![Span::raw("  "), level_icon(a.severity)]));
    let Some(src) = a.source.as_deref() else {
        // Unsourced findings (e.g. `conflicting-answers`, whose message
        // names every responder) take the empty source column too, so
        // their long text isn't clipped to the data column.
        cells.truncate(source_col);
        cells.push(
            Cell::from(finding_text(a, identity_count))
                .column_span((data_col - source_col + 1) as u16),
        );
        return Row::new(cells);
    };
    // A finding is about one responder: always name it (#246).
    let source = named(src.to_string(), book.resolve_label(src));
    cells[source_col] = Cell::from(source).style(Style::default().fg(Color::Gray));
    cells[data_col] = Cell::from(finding_text(a, identity_count));
    Row::new(cells)
}

/// `label (Name)`, or the label alone when no device is named (#246).
fn named(label: String, device: Option<DeviceName>) -> String {
    match device {
        Some(d) => format!("{label} ({})", d.display()),
        None => label,
    }
}

/// Hosts the displayed target lives on (its hostname and live SRV
/// targets): records answered by these need no device name.
fn own_hosts(target: &crate::app::DetailTarget<'_>) -> HashSet<String> {
    match target {
        crate::app::DetailTarget::Service(svc) => {
            let mut hosts: HashSet<String> = App::service_hosts(svc).into_iter().collect();
            hosts.insert(crate::anomalies::host_id(&svc.hostname));
            hosts
        }
        _ => HashSet::new(),
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

/// Short display form for a service type: `_http._tcp.local.` → `http.tcp`.
/// Only used for rendering; grouping and collapse keys keep the full name.
fn short_service_type(label: &str) -> String {
    let trimmed = label.trim_end_matches('.');
    let base = crate::browse::strip_local_suffix(trimmed).unwrap_or(trimmed);
    let joined: Vec<&str> = base
        .split('.')
        .map(|part| part.strip_prefix('_').unwrap_or(part))
        .collect();
    let joined = joined.join(".");
    if joined.is_empty() {
        label.to_string()
    } else {
        joined
    }
}

fn draw_service_list(frame: &mut Frame, area: ratatui::layout::Rect, app: &App, found: &[Anomaly]) {
    app.list_viewport
        .set(area.height.saturating_sub(2) as usize);
    let items = app.display_items();
    let anomaly_counts = App::anomaly_counts_in(found);

    // An Instance is last in its group if the next row is not another
    // Instance (i.e. next is a Host header or end of list).
    let is_last_instance = |pos: usize| {
        !matches!(
            items.get(pos + 1),
            Some(DisplayItem::Instance { .. })
                | Some(DisplayItem::Enum { .. })
                | Some(DisplayItem::Unattributed)
        )
    };

    let list_items: Vec<ListItem<'_>> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let is_selected = i == app.selected_display;
            match item {
                DisplayItem::Host { label } => {
                    let collapsed = app.is_host_collapsed(label);
                    let glyph = if collapsed { "▸" } else { "▾" };
                    let display = app.host_display_name(label);
                    let count = app.host_service_count(label);
                    let addrs = app.host_addresses(label);
                    let addr_suffix = match addrs.as_slice() {
                        [] => String::new(),
                        [first] => format!(" · {first}"),
                        [first, rest @ ..] => format!(" · {first} (+{})", rest.len()),
                    };
                    let base = if is_selected {
                        Style::default()
                            .add_modifier(Modifier::BOLD)
                            .fg(Color::Yellow)
                    } else {
                        Style::default()
                            .add_modifier(Modifier::BOLD)
                            .fg(Color::Blue)
                    };
                    // The hostname is italic: group headers describe
                    // app-side grouping, not wire records. Terminals
                    // without italic support render it plain.
                    // Host-owned findings count once, on the host header;
                    // the `(unattributed)` header carries its findings.
                    let owner = if label == crate::app::UNATTRIBUTED_HOST {
                        crate::anomalies::UNATTRIBUTED_SERVICE
                    } else {
                        label.as_str()
                    };
                    let mut spans = vec![
                        Span::styled(format!("{glyph} "), base),
                        Span::styled(display, base.add_modifier(Modifier::ITALIC)),
                        Span::styled(format!(" ({count}){addr_suffix}"), base),
                    ];
                    if label != crate::app::ENUM_HOST {
                        spans.extend(badge_spans(anomaly_counts.get(owner)));
                    }
                    ListItem::new(Line::from(spans))
                }
                DisplayItem::Instance { index } => {
                    let svc = &app.services[*index];
                    let last = is_last_instance(i);
                    let branch = if last { "└─" } else { "├─" };
                    let active = if svc.is_active { "●" } else { "○" };
                    // Host context lives in the group header, so rows lead
                    // with the graspable instance name; type and port share
                    // one badge: [type:port].
                    let short = short_service_type(&svc.service_type);
                    let badge = if svc.port > 0 {
                        format!("[{}:{}]", short, svc.port)
                    } else {
                        format!("[{short}]")
                    };
                    let mut spans = vec![Span::raw(format!(
                        "{branch} {active} {} {badge}",
                        svc.instance
                    ))];
                    spans.extend(badge_spans(anomaly_counts.get(
                        &crate::anomalies::service_id(&svc.instance, &svc.service_type),
                    )));
                    ListItem::new(Line::from(spans))
                }
                DisplayItem::Enum { index } => {
                    let entry = &app.enum_entries[*index];
                    let last = is_last_instance(i);
                    let branch = if last { "└─" } else { "├─" };
                    let mut spans = vec![Span::raw(format!(
                        "{branch} ● {} [enum]",
                        entry.name.trim_end_matches('.')
                    ))];
                    spans.extend(badge_spans(
                        anomaly_counts.get(crate::anomalies::ENUMERATION_SERVICE),
                    ));
                    ListItem::new(Line::from(spans))
                }
                DisplayItem::Unattributed => {
                    ListItem::new(Line::from(Span::raw("└─ ● findings without an owner")))
                }
            }
        })
        .collect();

    // Always show the selected row's host in the border title:
    // instance rows carry no host themselves, so the host would otherwise
    // be invisible once its group header scrolls out of view.
    let title = match app.display_items().get(app.selected_display) {
        Some(DisplayItem::Enum { .. }) => {
            format!(" Hosts: {} ", app.host_display_name(crate::app::ENUM_HOST))
        }
        Some(DisplayItem::Instance { index }) => {
            let key = app.services[*index]
                .hostname
                .trim_end_matches('.')
                .to_lowercase();
            format!(" Hosts: {} ", app.host_display_name(&key))
        }
        Some(DisplayItem::Host { label }) => {
            format!(" Hosts: {} ", app.host_display_name(label))
        }
        Some(DisplayItem::Unattributed) => {
            format!(" Hosts: {} ", crate::app::UNATTRIBUTED_HOST)
        }
        None => " Hosts ".to_string(),
    };
    let list = List::new(list_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(border_color(
                    app.focus == Focus::Services,
                    resize_active(app, DragMode::Vertical),
                )),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(HighlightSpacing::Always);

    let mut state = ListState::default()
        .with_offset(app.list_offset.get())
        // The highlight lives in the focused pane; Tab moves it along.
        .with_selected(if app.focus == Focus::Services {
            Some(app.selected_display)
        } else {
            None
        });
    frame.render_stateful_widget(list, area, &mut state);
    app.list_offset.set(state.offset());
}

fn draw_detail_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &App, found: &[Anomaly]) {
    // Right side: Answers table (with its findings inline) on top, its
    // questions below with their own captions (age, not TTL), hex dump of
    // the selected entry at the bottom. The abutting pane borders are the
    // drag handles.
    let answers = app.answers_pct.clamp(10, 70);
    let questions = app
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

    app.answers_rect.set(panes[0]);
    app.questions_rect.set(panes[1]);
    app.hex_rect.set(panes[2]);
    draw_records_tab(frame, panes[0], app, found);
    draw_questions_tab(frame, panes[1], app, found);
    draw_hex_tab(frame, panes[2], app);
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
    // Never glow behind the metrics overlay: it owns all input while open.
    !app.show_metrics && (app.drag == mode || app.hover.get() == mode)
}

fn draw_records_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App, found: &[Anomaly]) {
    let Some(target) = app.display_detail() else {
        let empty = Paragraph::new("No service selected").style(Style::default().fg(Color::Gray));
        frame.render_widget(empty, area);
        return;
    };

    let layout = app.answers_layout(&target, found);
    let shown = worst_of(layout.iter().filter_map(|l| match l {
        crate::app::AnswerLine::Finding { anomaly, .. } => Some(&**anomaly),
        _ => None,
    }));
    let book = app.address_book();
    let own = own_hosts(&target);
    let (rows, raw_positions) = detail_table_rows(app, &target, &layout, &book, &own);
    app.answers_rows
        .replace(Some(layout.iter().map(|l| l.owning_record()).collect()));
    let total_rows = rows.len();

    // Size SOURCE to the longest label (record rows and finding rows,
    // device names included) so IPv6 fits, clamped to keep RDATA usable
    // on narrow terminals.
    let finding_sources = layout.iter().filter_map(|l| match l {
        crate::app::AnswerLine::Finding { anomaly, .. } => anomaly
            .source
            .as_deref()
            .map(|src| named(src.to_string(), book.resolve_label(src)).len()),
        _ => None,
    });
    let src_w = target
        .all_answers()
        .iter()
        .map(|r| record_source_label(r, &book, &own).len())
        .chain(finding_sources)
        .max()
        .unwrap_or(14)
        // Device names (#246) lengthen labels: a wider cap keeps
        // `addr (one-shot, Name)` whole.
        .clamp(14, 60) as u16;

    // TYPE fits `▸ TXT` / `TYPE13` plus the level marker.
    let widths = [
        Constraint::Length(8),
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(src_w),
        Constraint::Min(20),
    ];

    let block_title = if app.detail_free_scroll {
        format!("Answers: {} ↕", target.pane_ident())
    } else {
        format!("Answers: {}", target.pane_ident())
    };
    let mut title_spans = vec![Span::raw(format!(" {block_title} "))];
    title_spans.extend(title_count_spans(shown));
    // Visible data rows: borders plus the header row are chrome.
    app.record_viewport
        .set(area.height.saturating_sub(3) as usize);

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["TYPE", "TTL", "FLUSH", "SOURCE", "RDATA"]).style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(title_spans))
                .border_style(border_color(
                    app.focus == Focus::Answers,
                    resize_active(app, DragMode::Vertical)
                        || resize_active(app, DragMode::HorizUpper),
                )),
        )
        // The hex pane follows the record cursor whatever holds focus, so
        // the cursor row stays marked even when unfocused — dimmed to stay
        // distinct from the focused cursor.
        .row_highlight_style(if app.focus == Focus::Answers {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::DIM)
        });

    // Highlight the record-cursor row, if the cursor is on a record, so
    // the hex source stays identifiable whatever holds focus (unfocused
    // panes mark it dimmed via the highlight style above).
    // TXT child rows are display-only; questions live in their own pane.
    // In free-scroll mode the selection is withheld so ratatui (which
    // always snaps the viewport back to the selected row) does not undo
    // the manual offset; the cursor itself is untouched (hex pane follows).
    let selected_table_row =
        if app.selected_detail_entry().is_some() && app.detail_selected < raw_positions.len() {
            Some(raw_positions[app.detail_selected])
        } else {
            None
        };
    // Auto-fit the selected record's child extent into view on
    // cursor-follow frames, so an `Enter` expansion near the bottom of
    // the pane reveals its children instead of clipping them. Capped to
    // keep the parent visible: oversized expansions pin the parent to
    // the top and show the first viewport-full of children (page the
    // rest with Ctrl-j/k).
    let mut offset = app.detail_offset.get();
    if !app.detail_free_scroll {
        if let Some(selected) = selected_table_row {
            let extent_end = raw_positions
                .get(app.detail_selected + 1)
                .copied()
                .unwrap_or(total_rows);
            let viewport = area.height.saturating_sub(3) as usize;
            offset = fit_row_extent(offset, selected, extent_end, viewport, total_rows);
        }
    } else {
        let viewport = area.height.saturating_sub(3) as usize;
        offset = offset.min(total_rows.saturating_sub(viewport));
        offset = offset.min(total_rows.saturating_sub(1));
    }
    let mut tstate = TableState::default();
    // In free-scroll mode the selection is withheld so ratatui (which
    // always snaps the viewport back to the selected row) does not undo
    // the manual offset; otherwise the marker stays visible whatever
    // holds focus, so the hex source row is always identifiable.
    tstate.select(if app.detail_free_scroll {
        None
    } else {
        selected_table_row
    });
    *tstate.offset_mut() = offset;
    frame.render_stateful_widget(table, area, &mut tstate);
    app.detail_offset.set(tstate.offset());
}

/// Viewport offset that keeps `selected` visible and pulls the child
/// extent `[selected, extent_end)` into view when it fits; oversized
/// extents pin the parent to the top. Pure helper, unit-tested below.
fn fit_row_extent(
    offset: usize,
    selected: usize,
    extent_end: usize,
    viewport: usize,
    total: usize,
) -> usize {
    if viewport == 0 || total == 0 {
        return 0;
    }
    let max_offset = total.saturating_sub(viewport);
    let mut fitted = offset.min(max_offset).min(selected);
    if extent_end > fitted + viewport {
        fitted = extent_end.saturating_sub(viewport).min(selected);
    }
    fitted.min(max_offset)
}

/// Source cell for the Records table (`RawRecord::source_label`).
fn source_label(rec: &crate::browse::RawRecord) -> String {
    rec.source_label()
}

/// Heat color for the TTL cell, aligned to the RFC 6762 §5.2 requery
/// schedule (`requery_expiring` in `app.rs` fires at ~80/85/90/95% of
/// the TTL): yellow while inside the refresh window (elapsed >= 80%,
/// a requery is due or in flight), red past the final refresh
/// (elapsed >= 95%) or expired, `None` for a healthy record (keep the
/// row style).
fn ttl_cell_color(rem: u32, ttl: u32) -> Option<Color> {
    if ttl == 0 || (rem as u64) * 20 <= ttl as u64 {
        Some(Color::Red)
    } else if (rem as u64) * 5 <= ttl as u64 {
        Some(Color::Yellow)
    } else {
        None
    }
}

fn detail_table_rows<'a>(
    app: &'a App,
    target: &'a crate::app::DetailTarget<'a>,
    layout: &[crate::app::AnswerLine],
    book: &AddressBook,
    own: &HashSet<String>,
) -> (Vec<Row<'a>>, Vec<usize>) {
    use crate::app::AnswerLine;
    let mut rows = Vec::new();

    let info_style = Style::default()
        .fg(Color::Green)
        .add_modifier(Modifier::ITALIC);
    let block_style = Style::default()
        .fg(Color::Cyan)
        .add_modifier(Modifier::BOLD | Modifier::ITALIC);
    // TXT pair children show verbatim wire content, so they stay
    // upright: only the constructed header rows are italic.
    let pair_style = Style::default().fg(Color::Green);
    let dim = Style::default().fg(Color::Gray);
    let local_style = Style::default()
        .fg(Color::Green)
        .add_modifier(Modifier::BOLD);

    // Raw answers, deduped and sorted by type then TTL (ordering lives on
    // the target so the j/k cursor and hex lookup share it). The layout
    // places finding child rows (always shown) before TXT pair children
    // (`Enter` folds those); the cursor skips every child row.
    // raw_positions maps each raw record to its table row.
    let answers = target.ordered_answers();
    let identity_count = crate::anomalies::identity_counts(layout.iter().filter_map(|l| match l {
        AnswerLine::Finding { anomaly, .. } => Some(&**anomaly),
        _ => None,
    }));
    let mut raw_positions = Vec::with_capacity(answers.len());
    // Worst finding per record and cell, in one pass: TTL kinds mark the
    // TTL cell, everything else the type cell. Gone rows carry no
    // findings in the layout, so they stay unmarked.
    let mut marks: Vec<(
        Option<crate::anomalies::Severity>,
        Option<crate::anomalies::Severity>,
    )> = vec![(None, None); answers.len()];
    for line in layout {
        if let AnswerLine::Finding {
            anomaly,
            record: Some(r),
        } = line
        {
            let Some(mark) = marks.get_mut(*r) else {
                continue;
            };
            let slot = if anomaly.kind.is_ttl() {
                &mut mark.0
            } else {
                &mut mark.1
            };
            if slot.is_none_or(|s| anomaly.severity.rank() > s.rank()) {
                *slot = Some(anomaly.severity);
            }
        }
    }
    for line in layout {
        match line {
            AnswerLine::Info { label, text } => rows.push(
                Row::new(vec![
                    Cell::from(*label),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(""),
                    Cell::from(text.clone()),
                ])
                .style(info_style),
            ),
            AnswerLine::Block(label) => rows
                .push(Row::new(vec![Cell::from(label.clone()).column_span(5)]).style(block_style)),
            AnswerLine::Finding { anomaly, .. } => {
                rows.push(finding_row(anomaly, &identity_count, book, 3, 4));
            }
            AnswerLine::TxtPair { pair, last, .. } => {
                // Children span the full row width so the pair text sits
                // next to the tree glyph instead of in RDATA.
                let branch = if *last { "  └─" } else { "  ├─" };
                rows.push(
                    Row::new(vec![Cell::from(Line::from(vec![
                        Span::raw(branch),
                        Span::raw(" "),
                        Span::raw(pair.clone()),
                    ]))
                    .column_span(5)])
                    .style(pair_style),
                );
            }
            AnswerLine::Record(i) => {
                let rec = answers[*i];
                let (ttl_mark, type_mark) = marks[*i];
                let flush = if rec.flush_bit { "flush" } else { "" };
                let rem = rec
                    .ttl
                    .saturating_sub(rec.received_at.elapsed().as_secs() as u32);
                // Gone rows name how they went: a goodbye (TTL 0,
                // withdrawn) reads `bye`, an elapsed TTL `exp`.
                let ttl_str = if rec.ttl == 0 {
                    "bye".into()
                } else if rem == 0 {
                    "exp".into()
                } else if rem >= 60 {
                    format!("{}m{:02}s", rem / 60, rem % 60)
                } else {
                    format!("{rem}s")
                };
                // Records announced by this host (source is a local
                // interface address) get a brighter style so own
                // publications stand out.
                let style = if app.is_local_record(rec) {
                    local_style
                } else {
                    dim
                };
                raw_positions.push(rows.len());
                let ttl_style = match ttl_cell_color(rem, rec.ttl) {
                    Some(color) => Style::default().fg(color),
                    None => Style::default(),
                };
                let type_label = if crate::app::App::is_expandable_txt(rec) {
                    if app.is_txt_expanded(rec) {
                        "▾ TXT"
                    } else {
                        "▸ TXT"
                    }
                } else {
                    rec.rtype_str.as_str()
                };
                rows.push(
                    Row::new(vec![
                        marked_cell(type_label.to_string(), type_mark, Style::default()),
                        marked_cell(ttl_str, ttl_mark, ttl_style),
                        Cell::from(flush),
                        Cell::from(record_source_label(rec, book, own)),
                        Cell::from(rec.rdata.clone()),
                    ])
                    .style(style),
                );
            }
        }
    }

    (rows, raw_positions)
}

fn draw_questions_tab(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    app: &App,
    found: &[Anomaly],
) {
    let Some(target) = app.display_detail() else {
        let empty = Paragraph::new("No service selected").style(Style::default().fg(Color::Gray));
        frame.render_widget(empty, area);
        return;
    };

    let dim = Style::default().fg(Color::Gray);
    let local_style = Style::default()
        .fg(Color::Green)
        .add_modifier(Modifier::BOLD);

    // By type, newest first — same grouping as the Answers table. Each
    // row is followed by its findings (keys are name, type, querier: each
    // querier keeps its own finding) and marked with the worst one.
    let book = app.address_book();
    let per_question = app.question_findings(&target, found);
    let shown = worst_of(per_question.iter().flatten());
    let identity_count = crate::anomalies::identity_counts(per_question.iter().flatten());
    // Cells plus row style first: LAST/DUE widths size to content
    // (like SOURCE below) instead of clipping long states.
    let mut body: Vec<(Vec<String>, Style)> = Vec::new();
    let mut marks = Vec::new();
    for (q, (name, rtype, source, seen_at, _)) in target.ordered_questions().into_iter().enumerate()
    {
        // Latest event and owning timer for this interest, from the
        // authoritative per-interest state (app.rs): rows stay dumb.
        let self_row = *source == crate::app::SELF_SOURCE;
        let (last_txt, due_txt) = match crate::browse::rtype_from_str(rtype) {
            Some(t) => {
                let s = app.interest_summary(name, t);
                let now = std::time::Instant::now();
                let last = if self_row {
                    // Our own send or §7.3 suppression: never "observed".
                    // Compare the original instants (not rounded ages) so
                    // the newer event wins even within the same second.
                    let selected = match (s.last_transmitted_at, s.last_suppressed_at) {
                        (Some(t), Some(u)) if u > t => {
                            Some((crate::app::QueryOrigin::Suppressed, u))
                        }
                        (Some(t), Some(_)) => Some((crate::app::QueryOrigin::Transmitted, t)),
                        (Some(t), None) => Some((crate::app::QueryOrigin::Transmitted, t)),
                        (None, Some(u)) => Some((crate::app::QueryOrigin::Suppressed, u)),
                        (None, None) => None,
                    };
                    match selected {
                        Some((origin, at)) => {
                            let age = now.saturating_duration_since(at).as_secs();
                            format!("{} {}", fmt_qage(age), origin.as_str())
                        }
                        None => "—".to_string(),
                    }
                } else {
                    // Foreign querier: this row is an observation.
                    let age = now.saturating_duration_since(*seen_at).as_secs();
                    format!("{} observed", fmt_qage(age))
                };
                // DUE is schedule ownership: only our own inferred sends
                // (self rows) own a timer. A foreign querier's row never
                // claims our refresh/browse/expired schedule, even when
                // the interest itself is one we maintain.
                let due = if self_row {
                    use crate::app::TimerKind;
                    match (s.timer, s.next_due_in_secs) {
                        (TimerKind::Refresh | TimerKind::Browse, Some(d)) => {
                            format!("{} {}", fmt_qage(d), s.timer.as_str())
                        }
                        // No schedule: "expired" only for lapsed local demand.
                        _ if s.had_local_demand => TimerKind::Expired.as_str().to_string(),
                        _ => "—".to_string(),
                    }
                } else {
                    "—".to_string()
                };
                (last, due)
            }
            None => ("—".to_string(), "—".to_string()),
        };
        // Questions asked from this host's own addresses (including our
        // own looped-back queries) get the same highlight as local answers.
        // Our own inferred sends render as `self`.
        let style = if self_row || app.is_local_source(source) {
            local_style
        } else {
            dim
        };
        // Port 0 is never a real querier, so inferred self sends never
        // match a finding.
        marks.push(worst_of(&per_question[q]).map(|(_, s)| s));
        body.push((
            vec![
                rtype.clone(),
                last_txt,
                due_txt,
                question_source_label(source, &book),
                name.clone(),
            ],
            style,
        ));
    }

    // Content-sized with clamps: headers are shorter than any real
    // content, so the floor only matters when every cell is blank.
    let last_w = body
        .iter()
        .map(|(cells, _)| cells[1].len())
        .max()
        .unwrap_or(4)
        .clamp(8, 20) as u16;
    let due_w = body
        .iter()
        .map(|(cells, _)| cells[2].len())
        .max()
        .unwrap_or(3)
        .clamp(8, 15) as u16;
    let mut rows: Vec<Row> = Vec::new();
    let mut question_positions = Vec::with_capacity(body.len());
    // Row -> question index as drawn: finding rows belong to their question.
    let mut row_map = Vec::new();
    for (q, (cells, style)) in body.into_iter().enumerate() {
        question_positions.push(rows.len());
        row_map.extend(std::iter::repeat_n(Some(q), 1 + per_question[q].len()));
        let mut cells = cells.into_iter();
        let mut row_cells = vec![marked_cell(
            cells.next().unwrap_or_default(),
            marks[q],
            Style::default(),
        )];
        row_cells.extend(cells.map(Cell::from));
        rows.push(Row::new(row_cells).style(style));
        for a in &per_question[q] {
            rows.push(finding_row(a, &identity_count, &book, 3, 4));
        }
    }
    app.questions_rows.replace(Some(row_map));

    let widths = [
        Constraint::Length(8),
        Constraint::Length(last_w),
        Constraint::Length(due_w),
        Constraint::Length(
            target
                .ordered_questions()
                .iter()
                .map(|(_, _, source, _, _)| question_source_label(source, &book).len())
                .max()
                .unwrap_or(14)
                .clamp(14, 60) as u16,
        ),
        Constraint::Min(20),
    ];

    // The Questions table is its own focus stop: light its border when
    // focused.
    let raw_count = target.ordered_answers().len();
    let cursor_in_questions =
        app.selected_detail_entry().is_some() && app.detail_selected >= raw_count;

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["TYPE", "LAST", "DUE", "SOURCE", "QUESTION"]).style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(Line::from(
                    std::iter::once(Span::raw(format!(" Questions: {} ", target.pane_ident())))
                        .chain(title_count_spans(shown))
                        .collect::<Vec<_>>(),
                ))
                .border_style(border_color(
                    app.focus == Focus::Questions,
                    resize_active(app, DragMode::Vertical)
                        || resize_active(app, DragMode::HorizUpper)
                        || resize_active(app, DragMode::HorizLower),
                )),
        )
        // The hex pane follows the detail cursor whatever holds focus, so
        // the cursor row stays marked even when unfocused — dimmed to stay
        // distinct from the focused cursor.
        .row_highlight_style(if app.focus == Focus::Questions {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::DIM)
        });

    // Highlight the detail-cursor question row, if the cursor is on one,
    // so the hex source stays identifiable whatever holds focus.
    let selected_table_row = if cursor_in_questions {
        question_positions
            .get(app.detail_selected - raw_count)
            .copied()
    } else {
        None
    };
    let mut tstate = TableState::default();
    // The marker stays visible whatever holds focus; the focused cursor
    // keeps the full highlight, other focuses get the dimmed style above.
    tstate.select(if cursor_in_questions {
        selected_table_row
    } else {
        None
    });
    *tstate.offset_mut() = app.questions_offset.get();
    frame.render_stateful_widget(table, area, &mut tstate);
    app.questions_offset.set(tstate.offset());
}

/// Source cell for the Questions table: our own inferred sends render
/// as `self` (never named), one-shot resolvers (§5.1, ephemeral source
/// port) get a tag, everything else as the querier address; a named
/// device follows (`addr (Name)`, `addr (one-shot, Name)`).
fn question_source_label(source: &SocketAddr, book: &AddressBook) -> String {
    if *source == crate::app::SELF_SOURCE {
        return crate::app::SELF_SOURCE_LABEL.to_string();
    }
    let device = book.resolve(source.ip()).map(|d| d.display());
    match (crate::anomalies::is_one_shot_querier(source), device) {
        (true, Some(name)) => format!("{source} (one-shot, {name})"),
        (true, None) => format!("{source} (one-shot)"),
        (false, Some(name)) => format!("{source} ({name})"),
        (false, None) => source.to_string(),
    }
}

/// Compact age for query cells: `45s`, `3m02s`.
fn fmt_qage(secs: u64) -> String {
    if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}
struct HexFieldPosition {
    row: usize,
    col: usize,
    width: usize,
    index: usize,
}

struct HexDump {
    lines: Vec<Line<'static>>,
    field_positions: Vec<HexFieldPosition>,
}

fn draw_hex_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    // The hex pane follows the record cursor: wire bytes of the selected
    // record, the query packet of the selected question row, otherwise the
    // whole latest packet for the service. Tab focuses it; j/k and paging
    // keys then scroll, and the offset resets when the cursor moves.
    app.hex_viewport.set(area.height.saturating_sub(2) as usize);
    let (dump, title, selected_field_label) =
        if let Some((bytes, title)) = app.selected_detail_bytes() {
            let fields = app.selected_detail_fields().unwrap_or_default();
            let selected_field = app
                .hex_selected_field
                .get()
                .filter(|index| *index < fields.len());
            let selected_field_label =
                selected_field.and_then(|index| fields.get(index).map(|field| field.label.clone()));
            (
                hex_dump(
                    &bytes,
                    16,
                    area.width.saturating_sub(2) as usize,
                    &fields,
                    selected_field,
                ),
                title,
                selected_field_label,
            )
        } else if let Some(ev) = app.latest_event_for_selected() {
            (
                hex_dump(
                    &ev.raw_bytes,
                    16,
                    area.width.saturating_sub(2) as usize,
                    &[],
                    None,
                ),
                " Raw Packet ".to_string(),
                None,
            )
        } else {
            // In-pane focus cue (the hex pane has no cursor to highlight):
            // the body text goes bold while focused. The border already
            // brightens, but that alone is easy to miss when tabbing panes.
            let empty_style = if app.focus == Focus::Hex {
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let empty = Paragraph::new("No raw packet data available").style(empty_style);
            frame.render_widget(empty, area);
            app.hex_field_hits.borrow_mut().clear();
            return;
        };

    let total = dump.lines.len();
    let offset = clamp_scroll(app.hex_offset.get(), total, app.hex_viewport.get());
    app.hex_offset.set(offset);
    *app.hex_field_hits.borrow_mut() = dump
        .field_positions
        .iter()
        .filter_map(|position| {
            let content_row = 1 + position.row;
            if content_row < offset {
                return None;
            }
            let x = area.x.saturating_add(1 + position.col as u16);
            let y = area.y.saturating_add(1 + (content_row - offset) as u16);
            let right = area.x.saturating_add(area.width).saturating_sub(1);
            let bottom = area.y.saturating_add(area.height).saturating_sub(1);
            let width = position.width.min(right.saturating_sub(x) as usize) as u16;
            (width > 0 && y < bottom).then_some((Rect::new(x, y, width, 1), position.index))
        })
        .collect();
    let title = if offset > 0 {
        format!("{} ↕", title.trim_end())
    } else {
        title
    };
    let title = if let Some(label) = selected_field_label {
        Line::from(vec![
            Span::styled(
                format!(" {} ", label),
                Style::default()
                    .fg(Color::Yellow)
                    .add_modifier(Modifier::UNDERLINED),
            ),
            Span::raw(title),
        ])
    } else {
        Line::from(title)
    };
    let para = Paragraph::new(dump.lines)
        .scroll((offset as u16, 0))
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(border_color(
                    app.focus == Focus::Hex,
                    resize_active(app, DragMode::Vertical)
                        || resize_active(app, DragMode::HorizLower),
                )),
        )
        .style(if app.focus == Focus::Hex {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        });
    frame.render_widget(para, area);
}

fn hex_dump(
    data: &[u8],
    width: usize,
    field_width: usize,
    fields: &[crate::browse::RecordField],
    selected_field: Option<usize>,
) -> HexDump {
    let mut lines = Vec::new();
    let mut field_positions = Vec::new();

    lines.push(Line::from(Span::styled(
        format!("Hex dump ({} bytes):", data.len()),
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    )));
    if fields.is_empty() {
        lines.push(Line::from(""));
    } else {
        let (field_lines, positions) = hex_field_legend(fields, field_width, selected_field);
        lines.extend(field_lines);
        field_positions = positions;
        lines.push(Line::from(""));
    }

    for (chunk_idx, chunk) in data.chunks(width).enumerate() {
        let offset_str = format!("{:04x}  ", chunk_idx * width);
        let highlighted: Vec<bool> = chunk
            .iter()
            .enumerate()
            .map(|(byte_idx, _)| {
                let offset = chunk_idx * width + byte_idx;
                selected_field
                    .and_then(|index| fields.get(index))
                    .is_some_and(|field| (field.start..field.end).contains(&offset))
            })
            .collect();
        let mut spans = vec![Span::styled(offset_str, Style::default().fg(Color::Gray))];
        let mut hex_len = 0;
        for (byte_idx, byte) in chunk.iter().enumerate() {
            let style = hex_byte_style(highlighted[byte_idx]);
            spans.push(Span::styled(format!("{byte:02x}"), style));
            hex_len += 2;
            if byte_idx % 2 == 1 && byte_idx + 1 < chunk.len() {
                spans.push(Span::raw(" "));
                hex_len += 1;
            }
        }
        let hex_width = width * 3 - 1 + (width / 2) - 1;
        spans.push(Span::raw(" ".repeat(hex_width.saturating_sub(hex_len) + 2)));
        for (byte_idx, byte) in chunk.iter().enumerate() {
            let style = hex_byte_style(highlighted[byte_idx]);
            let ascii = if byte.is_ascii_graphic() || *byte == b' ' {
                *byte as char
            } else {
                '.'
            };
            spans.push(Span::styled(ascii.to_string(), style));
        }
        lines.push(Line::from(spans));
    }

    HexDump {
        lines,
        field_positions,
    }
}

fn hex_byte_style(highlighted: bool) -> Style {
    if highlighted {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::UNDERLINED)
    } else {
        Style::default()
    }
}

fn hex_field_legend(
    fields: &[crate::browse::RecordField],
    width: usize,
    selected_field: Option<usize>,
) -> (Vec<Line<'static>>, Vec<HexFieldPosition>) {
    if width == 0 {
        return (Vec::new(), Vec::new());
    }
    let mut lines = Vec::new();
    let mut positions = Vec::new();
    let mut spans = Vec::new();
    let mut row = 0;
    let mut col = 0;

    for (index, field) in fields.iter().enumerate() {
        let label: String = format!("{} [{:04x}..{:04x})", field.label, field.start, field.end)
            .chars()
            .take(width)
            .collect();
        let label_width = label.chars().count();
        let separator = if col == 0 { 0 } else { 2 };
        if col > 0 && col + separator + label_width > width {
            lines.push(Line::from(std::mem::take(&mut spans)));
            row += 1;
            col = 0;
        }
        if col > 0 {
            spans.push(Span::raw("  "));
            col += 2;
        }
        positions.push(HexFieldPosition {
            row,
            col,
            width: label_width,
            index,
        });
        let style = if selected_field == Some(index) {
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::UNDERLINED)
        } else {
            Style::default().fg(Color::Cyan)
        };
        spans.push(Span::styled(label, style));
        col += label_width;
    }
    if !spans.is_empty() {
        lines.push(Line::from(spans));
    }
    (lines, positions)
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
        assert_eq!(ttl_cell_color(0, 120), Some(Color::Red));
        assert_eq!(ttl_cell_color(10, 0), Some(Color::Red));
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
        // Parent at 8 with 3 children (extent end 12), viewport 10: the
        // old offset 0 clips the children, so scroll to 2.
        assert_eq!(fit_row_extent(0, 8, 12, 10, 20), 2);
        // Already visible: offset untouched.
        assert_eq!(fit_row_extent(2, 8, 12, 10, 20), 2);
        // No children (extent is the row itself): no scroll.
        assert_eq!(fit_row_extent(0, 3, 4, 10, 20), 0);
    }

    #[test]
    fn fit_row_extent_pins_oversized_expansion_to_parent() {
        // 10 children in a viewport of 5: cannot fit, so pin the parent
        // (row 8) to the top; the rest pages via Ctrl-j/k.
        assert_eq!(fit_row_extent(0, 8, 19, 5, 30), 8);
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
