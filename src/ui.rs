use std::collections::HashSet;
use std::io;
use std::io::IsTerminal;
use std::net::SocketAddr;

use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, Clear, HighlightSpacing, List, ListItem, ListState, Paragraph, Row,
    Table, TableState,
};
use ratatui::Frame;

use crate::app::{App, DisplayItem, Focus};

pub type Terminal = ratatui::Terminal<CrosstermBackend<io::Stdout>>;

pub fn try_init() -> io::Result<Option<Terminal>> {
    if !io::stdin().is_terminal() {
        return Ok(None);
    }
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    execute!(stdout, EnterAlternateScreen)?;
    let backend = CrosstermBackend::new(stdout);
    Terminal::new(backend).map(Some)
}

pub fn try_restore(initialized: bool) -> io::Result<()> {
    if !initialized {
        return Ok(());
    }
    disable_raw_mode()?;
    execute!(io::stdout(), LeaveAlternateScreen)?;
    Ok(())
}

pub fn draw(frame: &mut Frame, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Vertical)
        .constraints([Constraint::Length(3), Constraint::Min(0)])
        .split(frame.area());

    draw_header(frame, chunks[0], app);
    draw_body(frame, chunks[1], app);
    if app.show_metrics {
        draw_metrics_overlay(frame, app);
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
            "│ {} pkts │ {} svcs │ uptime {}  [q] quit [tab] pane [j/k] move [enter] fold [m] metrics",
            app.packet_count,
            app.services.len(),
            uptime_str
        )),
    ]);

    let header = Paragraph::new(line).block(
        Block::default()
            .borders(Borders::ALL)
            .border_style(Style::default().fg(Color::Gray)),
    );
    frame.render_widget(header, area);
}

fn draw_body(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let chunks = Layout::default()
        .direction(Direction::Horizontal)
        .constraints([Constraint::Ratio(1, 3), Constraint::Ratio(2, 3)])
        .split(area);

    draw_service_list(frame, chunks[0], app);
    draw_detail_panel(frame, chunks[1], app);
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

fn draw_metrics_overlay(frame: &mut Frame, app: &App) {
    let area = centered_rect(80, 85, frame.area());
    frame.render_widget(Clear, area);

    let rows = app.metrics_rows();
    let total = rows.len();
    let viewport = (area.height as usize).saturating_sub(4);
    app.metrics_viewport.set(viewport);
    let offset = clamp_scroll(app.metrics_scroll.get(), total, viewport);
    app.metrics_scroll.set(offset);

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
                    Cell::from(format!("  {k}")).style(key_style),
                    Cell::from(v).style(val_style),
                ])
            }
        })
        .collect();

    let widths = [Constraint::Percentage(38), Constraint::Percentage(62)];
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
                .title(" Metrics (m/Esc close · j/k scroll) ")
                .border_style(Style::default().fg(Color::White)),
        );

    let mut state = TableState::default();
    *state.offset_mut() = offset;
    frame.render_stateful_widget(table, area, &mut state);
    app.metrics_scroll.set(state.offset());
}

/// Short display form for a service type: `_http._tcp.local.` → `http.tcp`.
/// Only used for rendering; grouping and collapse keys keep the full name.
fn short_service_type(label: &str) -> String {
    let trimmed = label.trim_end_matches('.');
    let base = if trimmed.len() > ".local".len()
        && trimmed[trimmed.len() - ".local".len()..].eq_ignore_ascii_case(".local")
    {
        &trimmed[..trimmed.len() - ".local".len()]
    } else {
        trimmed
    };
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

fn draw_service_list(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    app.list_viewport
        .set(area.height.saturating_sub(2) as usize);
    let items = app.display_items();

    // An Instance is last in its group if the next row is not another
    // Instance (i.e. next is a Host header or end of list).
    let is_last_instance =
        |pos: usize| !matches!(items.get(pos + 1), Some(DisplayItem::Instance { .. }));

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
                    let line = Line::from(Span::styled(
                        format!("{glyph} {display} ({count}){addr_suffix}"),
                        if is_selected {
                            Style::default()
                                .add_modifier(Modifier::BOLD)
                                .fg(Color::Yellow)
                        } else {
                            Style::default()
                                .add_modifier(Modifier::BOLD)
                                .fg(Color::Blue)
                        },
                    ));
                    ListItem::new(line)
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
                    let style = Style::default();
                    ListItem::new(Line::from(Span::styled(
                        format!("{branch} {active} {} {badge}", svc.instance),
                        style,
                    )))
                }
            }
        })
        .collect();

    // Always show the selected row's host in the border title:
    // instance rows carry no host themselves, so the host would otherwise
    // be invisible once its group header scrolls out of view.
    let title = match app.display_items().get(app.selected_display) {
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
        None => " Hosts ".to_string(),
    };
    let list = List::new(list_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(if app.focus == Focus::Services {
                    Color::White
                } else {
                    Color::Gray
                })),
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

/// "instance @ host:port" identity used in the right-pane titles.
fn pane_ident(svc: &crate::app::ServiceEntry) -> String {
    let host = svc.hostname.trim_end_matches('.');
    if host.is_empty() {
        svc.instance.clone()
    } else if svc.port > 0 {
        format!("{} @ {}:{}", svc.instance, host, svc.port)
    } else {
        format!("{} @ {host}", svc.instance)
    }
}

fn draw_detail_panel(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    // Right side: Answers table on top, its questions in the middle with
    // their own captions (age, not TTL), hex dump of the selected entry
    // at the bottom. Answers and Questions share the same height; the hex
    // view keeps only what is left over.
    let panes = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
            Constraint::Ratio(1, 3),
        ])
        .split(area);

    draw_records_tab(frame, panes[0], app);
    draw_questions_tab(frame, panes[1], app);
    draw_hex_tab(frame, panes[2], app);
}

fn draw_records_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let Some(svc) = app.display_service() else {
        let empty = Paragraph::new("No service selected").style(Style::default().fg(Color::Gray));
        frame.render_widget(empty, area);
        return;
    };

    let (rows, raw_positions) = detail_table_rows(app, svc);
    let total_rows = rows.len();

    // Size SOURCE to the longest socket addr so IPv6 fits, clamped to
    // keep RDATA usable on narrow terminals.
    let src_w = svc
        .records
        .iter()
        .map(|r| source_label(r).len())
        .max()
        .unwrap_or(14)
        .clamp(14, 45) as u16;

    let widths = [
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(6),
        Constraint::Length(src_w),
        Constraint::Min(20),
    ];

    let block_title = if app.detail_free_scroll {
        format!("Answers: {} ↕", pane_ident(svc))
    } else {
        format!("Answers: {}", pane_ident(svc))
    };
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
                .title(format!(" {block_title} "))
                .border_style(Style::default().fg(if app.focus == Focus::Answers {
                    Color::White
                } else {
                    Color::Gray
                })),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    // Highlight the record-cursor row, if the cursor is on a record.
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
    tstate.select(if app.detail_free_scroll || app.focus != Focus::Answers {
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

/// Source cell for the Records table: the responder address, suffixed
/// with the ingress interface when pktinfo provided one, so multi-link
/// traffic can be told apart. The `%iface` zone notation is only valid
/// for IPv6 link-local unicast (RFC 4007); everything else uses `@iface`.
/// A link-local source that already carries a zone (scope id) is shown
/// as-is instead of gaining a second suffix.
fn source_label(rec: &crate::browse::RawRecord) -> String {
    if rec.iface.is_empty() {
        return rec.source.to_string();
    }
    match rec.source {
        SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() && v6.scope_id() == 0 => {
            format!("{}%{}", rec.source, rec.iface)
        }
        SocketAddr::V6(v6) if v6.ip().is_unicast_link_local() => rec.source.to_string(),
        _ => format!("{}@{}", rec.source, rec.iface),
    }
}

/// Heat color for the TTL cell by fraction of the original TTL
/// remaining: red when expired or nearly so (the record is being
/// re-queried around now), yellow while it approaches the refresh
/// window, `None` for a healthy record (keep the row style).
fn ttl_cell_color(rem: u32, ttl: u32) -> Option<Color> {
    if ttl == 0 || (rem as u64) * 5 < ttl as u64 {
        Some(Color::Red)
    } else if (rem as u64) * 2 < ttl as u64 {
        Some(Color::Yellow)
    } else {
        None
    }
}

fn detail_table_rows<'a>(
    app: &'a App,
    svc: &'a crate::app::ServiceEntry,
) -> (Vec<Row<'a>>, Vec<usize>) {
    let mut rows = Vec::new();

    let info_style = Style::default().fg(Color::Green);
    let dim = Style::default().fg(Color::Gray);
    let local_style = Style::default()
        .fg(Color::Green)
        .add_modifier(Modifier::BOLD);

    rows.push(
        Row::new(vec![
            Cell::from("srvc"),
            Cell::from(""),
            Cell::from(""),
            Cell::from(""),
            Cell::from(svc.service_type.clone()),
        ])
        .style(info_style),
    );

    let mut seen_sub = HashSet::new();
    for sub in &svc.subtypes {
        if !seen_sub.insert(sub) {
            continue;
        }
        rows.push(
            Row::new(vec![
                Cell::from("subt"),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(sub.clone()),
            ])
            .style(info_style),
        );
    }

    // Raw records, deduped and sorted by type then TTL.
    // (Ordering lives on ServiceEntry so the j/k cursor and hex lookup share it.)
    // Multi-pair TXT records carry their key=value pairs as collapsible
    // child rows (collapsed by default, `Enter` expands); the cursor skips
    // child rows. raw_positions maps each raw record to its table row.
    let unique_recs = svc.ordered_records();
    let mut raw_positions = Vec::with_capacity(unique_recs.len());
    for rec in unique_recs {
        let flush = if rec.flush_bit { "flush" } else { "" };
        let rem = rec
            .ttl
            .saturating_sub(rec.received_at.elapsed().as_secs() as u32);
        let ttl_str = if rem == 0 {
            "exp".into()
        } else if rem >= 60 {
            format!("{}m{:02}s", rem / 60, rem % 60)
        } else {
            format!("{rem}s")
        };
        // Records announced by this host (source is a local interface
        // address) get a brighter style so own publications stand out.
        let style = if app.is_local_record(rec) {
            local_style
        } else {
            dim
        };
        raw_positions.push(rows.len());
        let ttl_cell = match ttl_cell_color(rem, rec.ttl) {
            Some(color) => Cell::from(ttl_str.clone()).style(Style::default().fg(color)),
            None => Cell::from(ttl_str.clone()),
        };
        let expandable = crate::app::App::is_expandable_txt(rec);
        let type_label = if expandable {
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
                Cell::from(type_label),
                ttl_cell,
                Cell::from(flush),
                Cell::from(source_label(rec)),
                Cell::from(rec.rdata.clone()),
            ])
            .style(style),
        );
        if expandable && !app.is_txt_expanded(rec) {
            continue;
        }
        if rec.rtype == 16 {
            let mut seen_pair = HashSet::new();
            let mut pairs: Vec<&str> = rec
                .rdata
                .split("; ")
                .filter(|pair| !pair.is_empty() && seen_pair.insert(*pair))
                .collect();
            pairs.sort_by(|a, b| {
                let ka = a.split('=').next().unwrap_or(a);
                let kb = b.split('=').next().unwrap_or(b);
                ka.to_lowercase()
                    .cmp(&kb.to_lowercase())
                    .then_with(|| ka.cmp(kb))
                    .then_with(|| a.cmp(b))
            });
            // A lone pair is already fully shown in the parent row.
            if pairs.len() > 1 {
                for (n, pair) in pairs.iter().enumerate() {
                    let branch = if n + 1 == pairs.len() {
                        "└─"
                    } else {
                        "├─"
                    };
                    rows.push(
                        Row::new(vec![
                            Cell::from(""),
                            Cell::from(""),
                            Cell::from(""),
                            Cell::from(""),
                            Cell::from(format!("  {branch} {pair}")),
                        ])
                        .style(info_style),
                    );
                }
            }
        }
    }

    (rows, raw_positions)
}

fn draw_questions_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    let Some(svc) = app.display_service() else {
        let empty = Paragraph::new("No service selected").style(Style::default().fg(Color::Gray));
        frame.render_widget(empty, area);
        return;
    };

    let mut rows = Vec::new();
    let dim = Style::default().fg(Color::Gray);
    let local_style = Style::default()
        .fg(Color::Green)
        .add_modifier(Modifier::BOLD);

    // By type, newest first — same grouping as the Answers table.
    for (name, rtype, source, received, _) in svc.ordered_questions() {
        let age = received.elapsed().as_secs();
        let age_str = if age >= 60 {
            format!("{}m{:02}s", age / 60, age % 60)
        } else {
            format!("{age}s")
        };
        // Questions asked from this host's own addresses (including our
        // own looped-back queries) get the same highlight as local records.
        let style = if app.is_local_source(source) {
            local_style
        } else {
            dim
        };
        rows.push(
            Row::new(vec![
                Cell::from(rtype.clone()),
                Cell::from(age_str),
                Cell::from(source.to_string()),
                Cell::from(name.clone()),
            ])
            .style(style),
        );
    }

    let widths = [
        Constraint::Length(6),
        Constraint::Length(12),
        Constraint::Length(
            svc.questions
                .iter()
                .map(|(_, _, source, _, _)| source.to_string().len())
                .max()
                .unwrap_or(14)
                .clamp(14, 45) as u16,
        ),
        Constraint::Min(20),
    ];

    // The Questions table is its own focus stop: light its border when
    // focused.
    let raw_count = svc.ordered_records().len();
    let cursor_in_questions =
        app.selected_detail_entry().is_some() && app.detail_selected >= raw_count;

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["TYPE", "AGE", "SOURCE", "QUESTION"]).style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(format!(" Questions: {} ", pane_ident(svc)))
                .border_style(Style::default().fg(if app.focus == Focus::Questions {
                    Color::White
                } else {
                    Color::Gray
                })),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    // Highlight the record-cursor question row, if the cursor is on one.
    let selected_table_row = if cursor_in_questions {
        Some(app.detail_selected - raw_count)
    } else {
        None
    };
    let mut tstate = TableState::default();
    tstate.select(if app.focus == Focus::Questions {
        selected_table_row
    } else {
        None
    });
    *tstate.offset_mut() = app.questions_offset.get();
    frame.render_stateful_widget(table, area, &mut tstate);
    app.questions_offset.set(tstate.offset());
}

fn draw_hex_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    // The hex pane follows the record cursor: wire bytes of the selected
    // record, the query packet of the selected question row, otherwise the
    // whole latest packet for the service.
    if let Some((bytes, title)) = app.selected_detail_bytes() {
        let hex = hex_dump(&bytes, 16);
        let para = Paragraph::new(hex)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(title)
                    .border_style(Style::default().fg(Color::Gray)),
            )
            .style(Style::default().fg(Color::Green));
        frame.render_widget(para, area);
        return;
    }

    let Some(ev) = app.latest_event_for_selected() else {
        let empty =
            Paragraph::new("No raw packet data available").style(Style::default().fg(Color::Gray));
        frame.render_widget(empty, area);
        return;
    };

    let hex = hex_dump(&ev.raw_bytes, 16);
    let para = Paragraph::new(hex)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(" Raw Packet ")
                .border_style(Style::default().fg(Color::Gray)),
        )
        .style(Style::default().fg(Color::Green));

    frame.render_widget(para, area);
}

fn hex_dump(data: &[u8], width: usize) -> Vec<Line<'_>> {
    let mut lines = Vec::new();

    lines.push(Line::from(Span::styled(
        format!("Hex dump ({} bytes):", data.len()),
        Style::default()
            .add_modifier(Modifier::BOLD)
            .fg(Color::Cyan),
    )));
    lines.push(Line::from(""));

    for (chunk_idx, chunk) in data.chunks(width).enumerate() {
        let hex: String = chunk
            .iter()
            .map(|b| format!("{:02x}", b))
            .collect::<Vec<_>>()
            .chunks(2)
            .map(|pair| pair.join(""))
            .collect::<Vec<_>>()
            .join(" ");
        let ascii: String = chunk
            .iter()
            .map(|b| {
                if b.is_ascii_graphic() || *b == b' ' {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();

        let offset_str = format!("{:04x}  ", chunk_idx * width);
        let padded_hex = format!("{:width$}", hex, width = width * 3 - 1 + (width / 2) - 1);

        lines.push(Line::from(vec![
            Span::styled(offset_str, Style::default().fg(Color::Gray)),
            Span::raw(format!("{padded_hex}  {ascii}")),
        ]));
    }

    lines
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn test_record(iface: &str) -> crate::browse::RawRecord {
        crate::browse::RawRecord {
            name: "_http._tcp.local.".to_string(),
            rtype: 12,
            rtype_str: "PTR".to_string(),
            flush_bit: false,
            qu: false,
            ttl: 120,
            rdata: "Test._http._tcp.local.".to_string(),
            wire: Vec::new(),
            source: "192.168.1.5:5353".parse().unwrap(),
            iface: iface.to_string(),
            received_at: Instant::now(),
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
    fn ttl_cell_color_marks_expiry_fraction() {
        assert_eq!(ttl_cell_color(0, 120), Some(Color::Red));
        assert_eq!(ttl_cell_color(10, 0), Some(Color::Red));
        assert_eq!(ttl_cell_color(23, 120), Some(Color::Red));
        assert_eq!(ttl_cell_color(24, 120), Some(Color::Yellow));
        assert_eq!(ttl_cell_color(59, 120), Some(Color::Yellow));
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
}
