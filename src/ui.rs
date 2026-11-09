use std::collections::HashSet;
use std::io;
use std::io::IsTerminal;
use std::net::SocketAddr;

use crossterm::execute;
use crossterm::terminal::{
    disable_raw_mode, enable_raw_mode, EnterAlternateScreen, LeaveAlternateScreen,
};
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{
    Block, Borders, Cell, HighlightSpacing, List, ListItem, ListState, Paragraph, Row, Table,
    TableState,
};
use ratatui::Frame;

use crate::app::{App, DisplayItem};

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
            "│ {} pkts │ {} svcs │ uptime {}  [q] quit [space←→] fold [j/k] row",
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
    let items = app.display_items();

    // An Instance is last in its group if the next row is not another
    // Instance (i.e. next is a ServiceType header or end of list).
    let is_last_instance =
        |pos: usize| !matches!(items.get(pos + 1), Some(DisplayItem::Instance { .. }));

    let list_items: Vec<ListItem<'_>> = items
        .iter()
        .enumerate()
        .map(|(i, item)| {
            let is_selected = i == app.selected_display;
            match item {
                DisplayItem::ServiceType { label } => {
                    let collapsed = app.is_type_collapsed(label);
                    let glyph = if collapsed { "▸" } else { "▾" };
                    let count = app.service_type_count(label);
                    let short = short_service_type(label);
                    let line = Line::from(Span::styled(
                        format!("{glyph} {short} ({count})"),
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
                    // One uniform style for all rows: the leading ●/○
                    // carries the state and the list's bold highlight
                    // marks the cursor. Same instance@host:port notation
                    // as the right-pane titles.
                    let style = Style::default();
                    ListItem::new(Line::from(Span::styled(
                        format!("{branch} {active} {}", pane_ident(svc)),
                        style,
                    )))
                }
            }
        })
        .collect();

    // Always show the selected row's service type in the border title:
    // instance rows carry no type themselves, so the type would otherwise
    // be invisible once its group header scrolls out of view.
    let title = match app.display_items().get(app.selected_display) {
        Some(DisplayItem::Instance { index }) => format!(
            " Services: {} ",
            short_service_type(&app.services[*index].service_type)
        ),
        Some(DisplayItem::ServiceType { label }) => {
            format!(" Services: {} ", short_service_type(label))
        }
        None => " Services ".to_string(),
    };
    let list = List::new(list_items)
        .block(
            Block::default()
                .borders(Borders::ALL)
                .title(title)
                .border_style(Style::default().fg(Color::Gray)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(HighlightSpacing::Always);

    let mut state = ListState::default()
        .with_offset(app.list_offset.get())
        .with_selected(Some(app.selected_display));
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
            Constraint::Percentage(40),
            Constraint::Percentage(40),
            Constraint::Percentage(20),
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

    let block_title = format!("Answers: {}", pane_ident(svc));

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
                .border_style(Style::default().fg(Color::Gray)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    // Highlight the j/k-selected row, if the cursor is on a record.
    // TXT child rows are display-only; questions live in their own pane.
    let selected_table_row =
        if app.selected_detail_entry().is_some() && app.detail_selected < raw_positions.len() {
            Some(raw_positions[app.detail_selected])
        } else {
            None
        };
    let mut tstate = TableState::default();
    tstate.select(selected_table_row);
    *tstate.offset_mut() = app.detail_offset.get();
    frame.render_stateful_widget(table, area, &mut tstate);
    app.detail_offset.set(tstate.offset());
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

    if !svc.hostname.is_empty() {
        let port_str = if svc.port > 0 {
            format!(":{}", svc.port)
        } else {
            String::new()
        };
        rows.push(
            Row::new(vec![
                Cell::from("host"),
                Cell::from(""),
                Cell::from(""),
                Cell::from(""),
                Cell::from(format!("{}{}", svc.hostname, port_str)),
            ])
            .style(info_style),
        );
    }

    // Raw records, deduped and sorted by type then TTL.
    // (Ordering lives on ServiceEntry so the j/k cursor and hex lookup share it.)
    // TXT records carry their key=value pairs as child rows which the cursor
    // skips; raw_positions maps each raw record to its table row.
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
        rows.push(
            Row::new(vec![
                Cell::from(rec.rtype_str.clone()),
                Cell::from(ttl_str.clone()),
                Cell::from(flush),
                Cell::from(source_label(rec)),
                Cell::from(rec.rdata.clone()),
            ])
            .style(style),
        );
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

    // Newest first, matching the j/k cursor order.
    for (name, rtype, source, received, _) in svc.questions.iter().rev() {
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
                .border_style(Style::default().fg(Color::Gray)),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED));

    // Highlight the j/k-selected question row, if the cursor is on one.
    let raw_count = svc.ordered_records().len();
    let selected_table_row =
        if app.selected_detail_entry().is_some() && app.detail_selected >= raw_count {
            Some(app.detail_selected - raw_count)
        } else {
            None
        };
    let mut tstate = TableState::default();
    tstate.select(selected_table_row);
    *tstate.offset_mut() = app.questions_offset.get();
    frame.render_stateful_widget(table, area, &mut tstate);
    app.questions_offset.set(tstate.offset());
}

fn draw_hex_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    // The hex pane follows the j/k cursor: wire bytes of the selected
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
}
