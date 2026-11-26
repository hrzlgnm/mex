// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// Hosts the displayed target lives on (its hostname and live SRV
/// targets): records answered by these need no device name.
pub(super) fn own_hosts(target: &crate::app::DetailTarget<'_>) -> HashSet<String> {
    match target {
        crate::app::DetailTarget::Service(svc) => {
            let mut hosts: HashSet<String> = App::service_hosts(svc).into_iter().collect();
            hosts.insert(crate::anomalies::host_id(&svc.hostname));
            hosts
        }
        _ => HashSet::new(),
    }
}

pub(super) fn draw_records_tab(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    app: &App,
    found: &[Anomaly],
) {
    let Some(target) = app.display_detail() else {
        // Keep the focus/resize cues even with nothing to show: the pane is
        // still a Tab stop, so it must keep its border when focused.
        let focused = app.view_state().focus == Focus::Answers;
        let empty = Paragraph::new("No service selected")
            .style(Style::default().fg(Color::Gray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(pane_border_type(focused))
                    .title(" Answers ")
                    .border_style(border_color(
                        focused,
                        resize_active(app, DragMode::Vertical)
                            || resize_active(app, DragMode::HorizUpper),
                    )),
            );
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
    app.layout()
        .answers_rows
        .replace(Some(layout.iter().map(|l| l.owning_record()).collect()));
    let total_rows = rows.len();

    // Size SOURCE to the longest label (record rows and finding rows,
    // device names included) so IPv6 fits, clamped to keep RDATA usable
    // on narrow terminals.
    // Only findings without a parent row draw a source (#266).
    let finding_sources = layout.iter().filter_map(|l| match l {
        crate::app::AnswerLine::Finding {
            anomaly,
            record: None,
        } => anomaly
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
        Constraint::Length(4),
        Constraint::Length(src_w),
        Constraint::Min(20),
    ];

    let block_title = if app.view_state().detail_free_scroll {
        format!("Answers: {} ↕", target.pane_ident())
    } else {
        format!("Answers: {}", target.pane_ident())
    };
    let mut title_spans = vec![Span::raw(format!(" {block_title} "))];
    title_spans.extend(title_count_spans(shown));
    // Visible data rows: borders plus the header row are chrome.
    app.layout()
        .record_viewport
        .set(area.height.saturating_sub(3) as usize);

    let table = Table::new(rows, widths)
        .header(
            Row::new(vec!["TYPE", "TTL", "FLUSH", "SECT", "SOURCE", "RDATA"]).style(
                Style::default()
                    .add_modifier(Modifier::BOLD)
                    .fg(Color::Cyan),
            ),
        )
        .block(
            Block::default()
                .borders(Borders::ALL)
                .border_type(pane_border_type(app.view_state().focus == Focus::Answers))
                .title(Line::from(title_spans))
                .border_style(border_color(
                    app.view_state().focus == Focus::Answers,
                    resize_active(app, DragMode::Vertical)
                        || resize_active(app, DragMode::HorizUpper),
                )),
        )
        // The hex pane follows the record cursor whatever holds focus, so
        // the cursor row stays marked even when unfocused — dimmed to stay
        // distinct from the focused cursor.
        .row_highlight_style(if app.view_state().focus == Focus::Answers {
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
    let selected_table_row = if app.selected_detail_entry().is_some()
        && app.view_state().detail_selected < raw_positions.len()
    {
        Some(raw_positions[app.view_state().detail_selected])
    } else {
        None
    };
    // Auto-fit the selected record's child extent into view on
    // cursor-follow frames, so an `Enter` expansion near the bottom of
    // the pane reveals its children instead of clipping them. Capped to
    // keep the parent visible: oversized expansions pin the parent to
    // the top and show the first viewport-full of children (page the
    // rest with Ctrl-j/k).
    let mut offset = app.layout().detail_offset.get();
    if !app.view_state().detail_free_scroll {
        if let Some(selected) = selected_table_row {
            let extent_end = raw_positions
                .get(app.view_state().detail_selected + 1)
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
    tstate.select(if app.view_state().detail_free_scroll {
        None
    } else {
        selected_table_row
    });
    *tstate.offset_mut() = offset;
    frame.render_stateful_widget(table, area, &mut tstate);
    app.layout().detail_offset.set(tstate.offset());
}

/// Viewport offset that keeps `selected` visible and pulls the child
/// extent `[selected, extent_end)` into view when it fits; oversized
/// extents pin the parent to the top. Pure helper, unit-tested below.
pub(super) fn fit_row_extent(
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

/// Heat color for the TTL cell, aligned to the RFC 6762 §5.2 requery
/// schedule (`requery_expiring` in `app.rs` fires at ~80/85/90/95% of
/// the TTL): yellow while inside the refresh window (elapsed >= 80%,
/// a requery is due or in flight), red past the final refresh
/// (elapsed >= 95%) or expired, `None` for a healthy record (keep the
/// row style). A goodbye (TTL 0) is a clean withdrawal, not a fault:
/// dark gray, distinct from both red and the gray of live rows.
pub(super) fn ttl_cell_color(rem: u32, ttl: u32) -> Option<Color> {
    if ttl == 0 {
        Some(Color::DarkGray)
    } else if (rem as u64) * 20 <= ttl as u64 {
        Some(Color::Red)
    } else if (rem as u64) * 5 <= ttl as u64 {
        Some(Color::Yellow)
    } else {
        None
    }
}

pub(super) fn detail_table_rows<'a>(
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
                    Cell::from(""),
                    Cell::from(text.clone()),
                ])
                .style(info_style),
            ),
            AnswerLine::Block(label) => rows
                .push(Row::new(vec![Cell::from(label.clone()).column_span(6)]).style(block_style)),
            AnswerLine::Finding { anomaly, record } => {
                rows.push(finding_row(
                    anomaly,
                    &identity_count,
                    book,
                    4,
                    5,
                    record.is_some(),
                ));
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
                    .column_span(6)])
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
                        Cell::from(rec.section.short_label()),
                        Cell::from(record_source_label(rec, book, own)),
                        Cell::from(crate::browse::display_rdata(rec.rtype, &rec.rdata)),
                    ])
                    .style(style),
                );
            }
        }
    }

    (rows, raw_positions)
}
