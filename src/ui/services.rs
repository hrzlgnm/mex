use super::*;

/// Short display form for a service type: `_http._tcp.local.` → `http.tcp`.
/// Only used for rendering; grouping and collapse keys keep the full name.
pub(super) fn short_service_type(label: &str) -> String {
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

pub(super) fn draw_service_list(
    frame: &mut Frame,
    area: ratatui::layout::Rect,
    app: &App,
    found: &[Anomaly],
) {
    app.layout()
        .list_viewport
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
            let is_selected = i == app.view_state().selected_display;
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
                    let svc = &app.services()[*index];
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
                    let entry = &app.enum_entries()[*index];
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
    let title = match app.display_items().get(app.view_state().selected_display) {
        Some(DisplayItem::Enum { .. }) => {
            format!(" Hosts: {} ", app.host_display_name(crate::app::ENUM_HOST))
        }
        Some(DisplayItem::Instance { index }) => {
            let key = app.services()[*index]
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
                    app.view_state().focus == Focus::Services,
                    resize_active(app, DragMode::Vertical),
                )),
        )
        .highlight_style(Style::default().add_modifier(Modifier::REVERSED))
        .highlight_spacing(HighlightSpacing::Always);

    let mut state = ListState::default()
        .with_offset(app.layout().list_offset.get())
        // The highlight lives in the focused pane; Tab moves it along.
        .with_selected(if app.view_state().focus == Focus::Services {
            Some(app.view_state().selected_display)
        } else {
            None
        });
    frame.render_stateful_widget(list, area, &mut state);
    app.layout().list_offset.set(state.offset());
}
