// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

pub(super) struct HexFieldPosition {
    pub(super) row: usize,
    pub(super) col: usize,
    pub(super) width: usize,
    pub(super) index: usize,
}

pub(super) struct HexDump {
    pub(super) lines: Vec<Line<'static>>,
    pub(super) field_positions: Vec<HexFieldPosition>,
}

pub(super) fn draw_hex_tab(frame: &mut Frame, area: ratatui::layout::Rect, app: &App) {
    // The hex pane follows the record cursor: wire bytes of the selected
    // record, the query packet of the selected question row, otherwise the
    // whole latest packet for the service. Tab focuses it; j/k and paging
    // keys then scroll, and the offset resets when the cursor moves.
    app.layout()
        .hex_viewport
        .set(area.height.saturating_sub(2) as usize);
    let (dump, title, selected_field_label) =
        if let Some((bytes, title)) = app.selected_detail_bytes() {
            let fields = app.selected_detail_fields().unwrap_or_default();
            let selected_field = app
                .view_state()
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
            let empty_style = if app.view_state().focus == Focus::Hex {
                Style::default()
                    .fg(Color::Gray)
                    .add_modifier(Modifier::BOLD)
            } else {
                Style::default().fg(Color::Gray)
            };
            let empty = Paragraph::new("No raw packet data available").style(empty_style);
            frame.render_widget(empty, area);
            app.layout().hex_field_hits.borrow_mut().clear();
            return;
        };

    let total = dump.lines.len();
    let offset = clamp_scroll(
        app.layout().hex_offset.get(),
        total,
        app.layout().hex_viewport.get(),
    );
    app.layout().hex_offset.set(offset);
    *app.layout().hex_field_hits.borrow_mut() = dump
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
                    app.view_state().focus == Focus::Hex,
                    resize_active(app, DragMode::Vertical)
                        || resize_active(app, DragMode::HorizLower),
                )),
        )
        .style(if app.view_state().focus == Focus::Hex {
            Style::default()
                .fg(Color::Green)
                .add_modifier(Modifier::BOLD)
        } else {
            Style::default().fg(Color::Green)
        });
    frame.render_widget(para, area);
}

pub(super) fn hex_dump(
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

pub(super) fn hex_byte_style(highlighted: bool) -> Style {
    if highlighted {
        Style::default()
            .fg(Color::Yellow)
            .add_modifier(Modifier::UNDERLINED)
    } else {
        Style::default()
    }
}

pub(super) fn hex_field_legend(
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
