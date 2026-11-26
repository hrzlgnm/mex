// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

pub(super) fn draw_questions_tab(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    app: &App,
    found: &[Anomaly],
) {
    let Some(target) = app.display_detail() else {
        // Same empty-state treatment as Answers: the pane stays a Tab stop,
        // so its focus/resize cues must survive an empty target.
        let focused = app.view_state().focus == Focus::Questions;
        let empty = Paragraph::new("No service selected")
            .style(Style::default().fg(Color::Gray))
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .border_type(pane_border_type(focused))
                    .title(" Questions ")
                    .border_style(border_color(
                        focused,
                        resize_active(app, DragMode::Vertical)
                            || resize_active(app, DragMode::HorizUpper)
                            || resize_active(app, DragMode::HorizLower),
                    )),
            );
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
                crate::browse::unescape_name(name),
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
            rows.push(finding_row(a, &identity_count, &book, 3, 4, true));
        }
    }
    app.layout().questions_rows.replace(Some(row_map));

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
        app.selected_detail_entry().is_some() && app.view_state().detail_selected >= raw_count;

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
                .border_type(pane_border_type(app.view_state().focus == Focus::Questions))
                .title(Line::from(
                    std::iter::once(Span::raw(format!(" Questions: {} ", target.pane_ident())))
                        .chain(title_count_spans(shown))
                        .collect::<Vec<_>>(),
                ))
                .border_style(border_color(
                    app.view_state().focus == Focus::Questions,
                    resize_active(app, DragMode::Vertical)
                        || resize_active(app, DragMode::HorizUpper)
                        || resize_active(app, DragMode::HorizLower),
                )),
        )
        // The hex pane follows the detail cursor whatever holds focus, so
        // the cursor row stays marked even when unfocused — dimmed to stay
        // distinct from the focused cursor.
        .row_highlight_style(if app.view_state().focus == Focus::Questions {
            Style::default().add_modifier(Modifier::REVERSED)
        } else {
            Style::default().add_modifier(Modifier::REVERSED | Modifier::DIM)
        });

    // Highlight the detail-cursor question row, if the cursor is on one,
    // so the hex source stays identifiable whatever holds focus.
    let selected_table_row = if cursor_in_questions {
        question_positions
            .get(app.view_state().detail_selected - raw_count)
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
    *tstate.offset_mut() = app.layout().questions_offset.get();
    frame.render_stateful_widget(table, area, &mut tstate);
    app.layout().questions_offset.set(tstate.offset());
}

/// Source cell for the Questions table: our own inferred sends render
/// as `self` (never named), one-shot resolvers (§5.1, ephemeral source
/// port) get a tag, everything else as the querier address; a named
/// device follows (`addr (Name)`, `addr (one-shot, Name)`).
pub(super) fn question_source_label(source: &SocketAddr, book: &AddressBook) -> String {
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
pub(super) fn fmt_qage(secs: u64) -> String {
    if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}
