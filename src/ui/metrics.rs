use super::*;

pub(super) fn draw_metrics_overlay(frame: &mut Frame, app: &App, found: &[Anomaly]) {
    let area = centered_rect(80, 85, frame.area());
    frame.render_widget(Clear, area);

    let rows = app.metrics_rows_in(found);
    let total = rows.len();
    let viewport = (area.height as usize).saturating_sub(4);
    app.layout().metrics_viewport.set(viewport);
    let offset = clamp_scroll(app.layout().metrics_scroll.get(), total, viewport);
    app.layout().metrics_scroll.set(offset);

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
        .layout()
        .metrics_hscroll
        .get()
        .min(longest.saturating_sub(value_w.max(1)));
    app.layout().metrics_hscroll.set(hscroll);

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
    app.layout().metrics_scroll.set(state.offset());
}

/// Skip `skip` chars of `s` for horizontal panning. Char-boundary safe;
/// the table truncates the tail to the visible width itself.
pub(super) fn shift_str(s: &str, skip: usize) -> String {
    if skip == 0 {
        return s.to_string();
    }
    s.chars().skip(skip).collect()
}
