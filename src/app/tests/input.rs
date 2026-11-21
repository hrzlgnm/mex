// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn txt_children_collapsed_by_default_and_enter_toggles() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2; c=3");
    let rec = app.services[0]
        .ordered_answers()
        .into_iter()
        .find(|r| r.rtype == 16)
        .cloned()
        .expect("TXT record merged into service");
    assert!(App::is_expandable_txt(&rec));
    assert!(!app.is_txt_expanded(&rec));
    assert!(app.toggle_txt_expanded());
    assert!(app.is_txt_expanded(&rec));
    assert!(app.toggle_txt_expanded());
    assert!(!app.is_txt_expanded(&rec));
}

#[test]
fn txt_single_pair_is_not_expandable() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1");
    let rec = app.services[0]
        .ordered_answers()
        .into_iter()
        .find(|r| r.rtype == 16)
        .cloned()
        .expect("TXT record merged into service");
    assert!(!App::is_expandable_txt(&rec));
    assert!(!app.toggle_txt_expanded());
}

#[test]
fn txt_enter_key_expands_and_falls_back() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let key = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    // Enter acts on the record cursor, so focus the Answers pane first.
    app.handle_key(&key(KeyCode::Tab));
    app.handle_key(&key(KeyCode::Enter));
    let rec = app.services[0]
        .ordered_answers()
        .into_iter()
        .find(|r| r.rtype == 16)
        .cloned()
        .unwrap();
    assert!(app.is_txt_expanded(&rec));
    // Second Enter collapses again.
    app.handle_key(&key(KeyCode::Enter));
    assert!(!app.is_txt_expanded(&rec));
}

#[test]
fn scroll_pins_viewport_and_cursor_resumes_follow() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let ctrl = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    let plain = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    assert!(!app.view_state.detail_free_scroll);
    // Ctrl+J now dumps state (like the sibling); viewport scroll
    // uses J instead.
    app.handle_key(&plain(KeyCode::Char('J')));
    assert!(app.view_state.detail_free_scroll);
    assert_eq!(app.layout.detail_offset.get(), 1);
    app.handle_key(&ctrl(KeyCode::Char('k')));
    assert_eq!(app.layout.detail_offset.get(), 0);
    // Tab focuses Answers; moving the record cursor resumes follow.
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Answers);
    let before = app.view_state.detail_selected;
    assert!(before > 0);
    app.handle_key(&plain(KeyCode::Char('k')));
    assert!(!app.view_state.detail_free_scroll);
    assert_eq!(app.view_state.detail_selected, before - 1);
    // Tab cycles Answers -> Questions -> Hex -> Services: no
    // Anomalies stop (#248).
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Questions);
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Hex);
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Services);
}

#[test]
fn tab_cycles_services_answers_questions() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = two_group_app();
    let plain = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    assert_eq!(app.view_state.focus, Focus::Services);
    // Service navigation in the Services pane: j moves to the next
    // selectable stop (Test).
    let stops = selectable_positions(&app);
    let test = stops[2];
    app.handle_key(&plain(KeyCode::Char('j')));
    assert_eq!(app.view_state.selected_display, test);
    let detail_before = app.view_state.detail_selected;
    // Tab focuses Answers: j now moves the record cursor instead.
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Answers);
    app.handle_key(&plain(KeyCode::Char('j')));
    assert_eq!(app.view_state.selected_display, test);
    assert_eq!(app.view_state.detail_selected, detail_before + 1);
    // BackTab steps back to Services.
    app.handle_key(&plain(KeyCode::BackTab));
    assert_eq!(app.view_state.focus, Focus::Services);
}

#[test]
fn questions_pane_moves_within_questions() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = two_group_app();
    let plain = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    // Two questions on the selected service, oldest first. The selected
    // service is the first host group (shell.local), not services[0].
    let src: std::net::SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let old = Instant::now() - Duration::from_secs(60);
    {
        let sel_idx = match app.display_items().get(app.view_state.selected_display) {
            Some(DisplayItem::Instance { index }) => *index,
            _ => panic!("expected instance selected"),
        };
        let svc = &mut app.services[sel_idx];
        svc.questions.push((
            "_http._tcp.local".to_string(),
            "PTR".to_string(),
            src,
            old,
            Vec::new(),
        ));
        svc.questions.push((
            "_http._tcp.local".to_string(),
            "PTR".to_string(),
            src,
            Instant::now(),
            Vec::new(),
        ));
    }
    let raw_count = app
        .display_service()
        .expect("service displayed")
        .ordered_answers()
        .len();
    // Tab twice to reach Questions; the cursor snaps to its first row.
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Answers);
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Questions);
    assert_eq!(app.view_state.detail_selected, raw_count);
    // j/k stay inside the question rows; the selection is untouched.
    let selected_before = app.view_state.selected_display;
    app.handle_key(&plain(KeyCode::Char('j')));
    assert_eq!(app.view_state.detail_selected, raw_count + 1);
    assert_eq!(app.view_state.selected_display, selected_before);
    app.handle_key(&plain(KeyCode::Char('k')));
    assert_eq!(app.view_state.detail_selected, raw_count);
    app.handle_key(&plain(KeyCode::Home));
    assert_eq!(app.view_state.detail_selected, raw_count);
    app.handle_key(&plain(KeyCode::End));
    assert_eq!(app.view_state.detail_selected, raw_count + 1);
    // Enter has nothing to expand here and must not fold the host.
    app.handle_key(&plain(KeyCode::Enter));
    assert!(app.collapsed_hosts.is_empty());
}

#[test]
fn enter_is_scoped_to_focused_pane() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let key = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    let rec = app.services[0]
        .ordered_answers()
        .into_iter()
        .find(|r| r.rtype == 16)
        .cloned()
        .expect("TXT record merged into service");
    // Services focus: Enter folds the host, never expands TXT.
    app.handle_key(&key(KeyCode::Enter));
    assert!(!app.is_txt_expanded(&rec));
    assert!(app.is_host_collapsed("test.local"));
    // Answers focus: Enter expands TXT instead.
    app.handle_key(&key(KeyCode::Char('+')));
    app.handle_key(&key(KeyCode::Tab));
    app.handle_key(&key(KeyCode::Enter));
    assert!(app.is_txt_expanded(&rec));
}

#[test]
fn records_home_end_and_paging() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let key = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.layout.record_viewport.set(2);
    app.handle_key(&key(KeyCode::Tab));
    app.handle_key(&key(KeyCode::End));
    assert_eq!(app.view_state.detail_selected, 2);
    app.handle_key(&key(KeyCode::Home));
    assert_eq!(app.view_state.detail_selected, 0);
    app.handle_key(&key(KeyCode::Char(' ')));
    assert_eq!(app.view_state.detail_selected, 2);
    app.handle_key(&key(KeyCode::Char('b')));
    assert_eq!(app.view_state.detail_selected, 0);
}

#[test]
fn home_end_on_an_empty_pane_keep_the_selection() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let key = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    // Last answer selected, then focus the (empty) Questions pane.
    app.handle_key(&key(KeyCode::Tab));
    app.handle_key(&key(KeyCode::End));
    let selected = app.view_state.detail_selected;
    app.handle_key(&key(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Questions);
    let anchor = app.detail_anchor.clone();
    assert!(anchor.is_some());
    // Like j/k there, Home/End have no row to move to: nothing changes.
    for code in [KeyCode::Home, KeyCode::End] {
        app.handle_key(&key(code));
        assert_eq!(app.view_state.detail_selected, selected, "{code:?}");
        assert!(
            app.detail_anchor == anchor,
            "{code:?} keeps the identity anchor"
        );
    }
}

#[test]
fn expand_clears_manual_scroll() {
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    app.scroll_detail(5);
    assert!(app.view_state.detail_free_scroll);
    assert!(app.toggle_txt_expanded());
    assert!(!app.view_state.detail_free_scroll);
}

#[cfg(unix)]
#[test]
fn ctrl_z_is_suspend_key() {
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    let ctrl = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    assert!(App::is_suspend_key(&ctrl(KeyCode::Char('z'))));
    assert!(!App::is_suspend_key(&plain_key(KeyCode::Char('z'))));
    assert!(!App::is_suspend_key(&ctrl(KeyCode::Char('c'))));
    assert!(!App::is_suspend_key(&ctrl(KeyCode::Char('Z'))));
    // Bare Alt is not enough; Ctrl combinations suspend, matching the
    // Ctrl+C quit binding and the sibling's `contains(CONTROL)` check.
    let alt_z = KeyEvent {
        modifiers: KeyModifiers::ALT,
        ..ctrl(KeyCode::Char('z'))
    };
    assert!(!App::is_suspend_key(&alt_z));
    let ctrl_alt_z = KeyEvent {
        modifiers: KeyModifiers::CONTROL | KeyModifiers::ALT,
        ..ctrl(KeyCode::Char('z'))
    };
    assert!(App::is_suspend_key(&ctrl_alt_z));
}

#[test]
fn jk_moves_service_selection() {
    let mut app = two_group_app();
    // Cursor starts on Shell; j moves to Test, k back to Shell.
    let shell = selectable_positions(&app)[1];
    let test = selectable_positions(&app)[2];
    assert_eq!(app.view_state.selected_display, shell);
    app.handle_key(&plain_key(KeyCode::Char('j')));
    assert_eq!(app.view_state.selected_display, test);
    app.handle_key(&plain_key(KeyCode::Char('k')));
    assert_eq!(app.view_state.selected_display, shell);
}

#[test]
fn hl_jumps_between_groups() {
    let mut app = two_group_app();
    let stops = selectable_positions(&app);
    let (first, shell, test) = (stops[0], stops[1], stops[2]);
    assert_eq!(app.view_state.selected_display, shell);
    app.handle_key(&plain_key(KeyCode::Char('l')));
    assert_eq!(app.view_state.selected_display, test);
    app.handle_key(&plain_key(KeyCode::Char('h')));
    assert_eq!(app.view_state.selected_display, shell);
    // Shift jumps to the first/last group.
    app.handle_key(&plain_key(KeyCode::Char('L')));
    assert_eq!(app.view_state.selected_display, *stops.last().unwrap());
    app.handle_key(&plain_key(KeyCode::Char('H')));
    assert_eq!(app.view_state.selected_display, first);
}

#[test]
fn arrows_jump_between_groups_like_hl() {
    let mut app = two_group_app();
    let stops = selectable_positions(&app);
    let (shell, test) = (stops[1], stops[2]);
    assert_eq!(app.view_state.selected_display, shell);
    app.handle_key(&plain_key(KeyCode::Right));
    assert_eq!(app.view_state.selected_display, test);
    app.handle_key(&plain_key(KeyCode::Left));
    assert_eq!(app.view_state.selected_display, shell);
}

#[test]
fn home_end_and_space_paging() {
    let mut app = two_group_app();
    app.layout.list_viewport.set(2);
    let stops = selectable_positions(&app);
    let (first, last) = (stops[0], *stops.last().unwrap());
    app.handle_key(&plain_key(KeyCode::End));
    assert_eq!(app.view_state.selected_display, last);
    app.handle_key(&plain_key(KeyCode::Home));
    assert_eq!(app.view_state.selected_display, first);
    // Space pages down one viewport (2 stops); b pages back up.
    app.handle_key(&plain_key(KeyCode::Char(' ')));
    assert_eq!(app.view_state.selected_display, stops[2]);
    assert!(app.collapsed_hosts.is_empty());
    app.handle_key(&plain_key(KeyCode::Char('b')));
    assert_eq!(app.view_state.selected_display, first);
}

#[test]
fn shift_arrows_and_jk_scroll_detail() {
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let shift = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(&shift(KeyCode::Down));
    assert!(app.view_state.detail_free_scroll);
    assert_eq!(app.layout.detail_offset.get(), 1);
    app.handle_key(&plain_key(KeyCode::Char('J')));
    assert_eq!(app.layout.detail_offset.get(), 2);
    app.handle_key(&plain_key(KeyCode::Char('K')));
    assert_eq!(app.layout.detail_offset.get(), 1);
    app.handle_key(&shift(KeyCode::Up));
    assert_eq!(app.layout.detail_offset.get(), 0);
}

#[test]
fn shifted_jk_scroll_in_all_reported_shapes() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let plain = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    let shift = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::SHIFT,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    // Answers focus, where plain j/k move the record cursor.
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Answers);
    let cursor = app.view_state.detail_selected;
    // Uppercase, with and without SHIFT flagged (terminal-dependent).
    app.handle_key(&plain(KeyCode::Char('J')));
    app.handle_key(&shift(KeyCode::Char('J')));
    assert_eq!(app.layout.detail_offset.get(), 2);
    assert_eq!(app.view_state.detail_selected, cursor);
    app.handle_key(&plain(KeyCode::Char('K')));
    app.handle_key(&shift(KeyCode::Char('K')));
    assert_eq!(app.layout.detail_offset.get(), 0);
    assert_eq!(app.view_state.detail_selected, cursor);
    // Lowercase + SHIFT (other keyboard protocols) scrolls too and
    // never moves the cursor.
    app.handle_key(&shift(KeyCode::Char('j')));
    assert_eq!(app.layout.detail_offset.get(), 1);
    assert_eq!(app.view_state.detail_selected, cursor);
    app.handle_key(&shift(KeyCode::Char('k')));
    assert_eq!(app.layout.detail_offset.get(), 0);
    assert_eq!(app.view_state.detail_selected, cursor);
    assert!(app.view_state.detail_free_scroll);
    // Plain lowercase still moves the cursor instead of scrolling.
    app.handle_key(&plain(KeyCode::Char('k')));
    assert_eq!(app.view_state.detail_selected, cursor - 1);
}

#[test]
fn star_collapses_and_unfolds_all_groups() {
    let mut app = two_group_app();
    let star = plain_key(KeyCode::Char('*'));
    assert!(app.collapsed_hosts.is_empty());
    // First press collapses every group.
    app.handle_key(&star);
    assert_eq!(app.group_labels().len(), 3);
    for label in app.group_labels() {
        assert!(app.is_host_collapsed(&label), "collapsed: {label}");
    }
    // Cursor still sits on a selectable stop.
    let items = app.display_items();
    assert!(app.is_selectable(&items[app.view_state.selected_display]));
    // Second press unfolds everything again.
    app.handle_key(&star);
    assert!(app.collapsed_hosts.is_empty());
}

#[test]
fn star_from_mixed_state_collapses_all() {
    let mut app = two_group_app();
    let labels = app.group_labels();
    app.collapsed_hosts.insert(labels[0].clone());
    app.handle_key(&plain_key(KeyCode::Char('*')));
    for label in app.group_labels() {
        assert!(app.is_host_collapsed(&label), "collapsed: {label}");
    }
}

#[test]
fn mouse_pane_splits_clamp_and_convert() {
    use ratatui::layout::Rect;
    assert_eq!(App::clamp_left_pct(5), 15);
    assert_eq!(App::clamp_left_pct(95), 80);
    assert_eq!(App::clamp_left_pct(40), 40);
    let body = Rect::new(0, 3, 100, 20);
    assert_eq!(App::pct_from_x(5, body), 5);
    assert_eq!(App::pct_from_x(50, body), 50);
    let right = Rect::new(33, 3, 67, 30);
    assert_eq!(App::pct_from_y(3 + 15, right), 50);
    // Hex keeps at least 10%: answers + questions + anomalies <= 90.
    // The second argument is the sum of the other two shares.
    assert_eq!(App::clamp_pane_pct(80, 45), 45);
    assert_eq!(App::clamp_pane_pct(80, 50), 40);
    assert_eq!(App::clamp_pane_pct(80, 55), 35);
    assert_eq!(App::clamp_pane_pct(30, 45), 30);
}

#[test]
fn mouse_drag_moves_splits_with_clamp() {
    use ratatui::layout::Rect;
    let mut app = App::new().unwrap();
    app.layout.body_rect.set(Rect::new(0, 3, 100, 40));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    app.set_left_from_x(5);
    assert_eq!(app.view_state.left_pct, 15);
    app.set_left_from_x(50);
    assert_eq!(app.view_state.left_pct, 50);
    app.view_state.questions_pct = 25;
    app.set_answers_from_y(3 + 27);
    assert_shares(&app);
    app.view_state.answers_pct = 50;
    app.set_questions_from_y(3 + 27);
    assert_shares(&app);
}

#[test]
fn mouse_down_drag_sequence_moves_seams() {
    let mut app = App::new().unwrap();
    // Seams come from the computed layout: the top border row of
    // the lower pane is always a grab zone.
    for mode in [DragMode::HorizUpper, DragMode::HorizLower] {
        app.view_state.answers_pct = 30;
        app.view_state.questions_pct = 25;
        render_to_buffer(&app, 100, 40);
        let (lower, before) = seam_target(&app, mode);
        assert!(lower.height > 2, "pane needs a grabbable border");
        app.handle_mouse(&mouse_down(lower.x + 5, lower.y));
        assert_eq!(app.view_state.drag, mode);
        app.handle_mouse(&mouse_drag(lower.x + 5, lower.y + 6));
        assert!(
            seam_target(&app, mode).1 > before,
            "{mode:?} drag must grow its share"
        );
        app.handle_mouse(&mouse_up(40, 20));
        assert_eq!(app.view_state.drag, DragMode::None);
        assert_shares(&app);
    }
    // Extremes through the mouse path: clamps hold and neighbors
    // keep their minimums.
    app.view_state.answers_pct = 30;
    app.view_state.questions_pct = 25;
    render_to_buffer(&app, 100, 40);
    let right = app.layout.right_rect.get();
    let bottom = right.y + right.height - 1;
    // Lower seam slammed to the bottom: questions pins at its max,
    // leaving hex its 10%.
    let (hex_top, _) = seam_target(&app, DragMode::HorizLower);
    app.handle_mouse(&mouse_down(hex_top.x + 5, hex_top.y));
    assert_eq!(app.view_state.drag, DragMode::HorizLower);
    app.handle_mouse(&mouse_drag(hex_top.x + 5, bottom));
    assert_eq!(app.view_state.drag, DragMode::HorizLower);
    assert_eq!(app.view_state.questions_pct, 60);
    assert_eq!(app.view_state.answers_pct, 30);
    // Upper seam slammed to the top: answers pins at 10%.
    let (questions_top, _) = seam_target(&app, DragMode::HorizUpper);
    app.handle_mouse(&mouse_down(questions_top.x + 5, questions_top.y));
    assert_eq!(app.view_state.drag, DragMode::HorizUpper);
    app.handle_mouse(&mouse_drag(questions_top.x + 5, right.y));
    assert_eq!(app.view_state.answers_pct, 10);
    assert_shares(&app);
}

/// Release ends the drag entirely: drag clears and hover is
/// recomputed from the release point, so a finished drag never
/// leaves the resize glow stuck (a motion-less terminal never
/// resyncs it). Release on a seam keeps the legitimate hover.
#[test]
fn mouse_up_resets_hover_from_release_point() {
    let mut app = two_group_app();
    for mode in [
        DragMode::Vertical,
        DragMode::HorizUpper,
        DragMode::HorizLower,
    ] {
        app.view_state.left_pct = 33;
        app.view_state.answers_pct = 30;
        app.view_state.questions_pct = 25;
        render_to_buffer(&app, 100, 40);
        let (col, row) = seam_grab_cell(&app, mode);
        let (dcol, drow) = match mode {
            DragMode::Vertical => (col - 5, row),
            _ => (col, row + 3),
        };
        // Off-seam release: the glow must go, not wait for a motion
        // event that button-motion-only terminals never send.
        app.handle_mouse(&mouse_down(col, row));
        assert_eq!(
            app.view_state.drag, mode,
            "{mode:?}: down must start the drag"
        );
        app.handle_mouse(&mouse_drag(dcol, drow));
        // Refresh the layout rects the drag just moved.
        render_to_buffer(&app, 100, 40);
        app.handle_mouse(&mouse_up(2, left_off_seam_row(&app)));
        assert_eq!(app.view_state.drag, DragMode::None);
        assert_eq!(
            app.view_state.hover.get(),
            DragMode::None,
            "{mode:?}: release away from any seam must clear the hover glow"
        );
        // On-seam release: the pointer rests on a grabbable seam, so
        // the hover glow legitimately stays. Re-grab wherever the seam
        // now sits, so the down is a real grab, not a stale position.
        render_to_buffer(&app, 100, 40);
        let (col, row) = seam_grab_cell(&app, mode);
        app.handle_mouse(&mouse_down(col, row));
        assert_eq!(
            app.view_state.drag, mode,
            "{mode:?}: re-grab must start the drag"
        );
        app.handle_mouse(&mouse_drag(dcol, drow));
        render_to_buffer(&app, 100, 40);
        let (col, row) = seam_grab_cell(&app, mode);
        app.handle_mouse(&mouse_up(col, row));
        assert_eq!(app.view_state.drag, DragMode::None);
        assert_eq!(
            app.view_state.hover.get(),
            mode,
            "{mode:?}: release on the seam must keep the hover glow"
        );
    }
}

/// A point inside the Hosts pane, off every seam grab zone.
fn left_off_seam_row(app: &App) -> u16 {
    let left = app.layout.left_rect.get();
    left.y.saturating_add(1)
}

/// A drag that did not start on a seam never resizes, but hover keeps
/// tracking the pointer while the button is held.
#[test]
fn drag_without_a_seam_start_tracks_hover_but_never_resizes() {
    let mut app = two_group_app();
    app.view_state.left_pct = 40;
    app.view_state.answers_pct = 30;
    app.view_state.questions_pct = 25;
    render_to_buffer(&app, 100, 40);
    let left = app.layout.left_rect.get();
    // Press inside the Hosts pane: no drag starts.
    app.handle_mouse(&mouse_down(2, left.y + 1));
    assert_eq!(app.view_state.drag, DragMode::None);
    // Drag away within the pane: no resize, hover stays empty.
    app.handle_mouse(&mouse_drag(5, left.y + 1));
    assert_eq!(
        app.view_state.left_pct, 40,
        "a drag that did not start on a seam must not resize"
    );
    assert_eq!(app.view_state.hover.get(), DragMode::None);
    // Crossing the vertical seam with the button held: hover follows,
    // resizing still does not start.
    let right = app.layout.right_rect.get();
    app.handle_mouse(&mouse_drag(right.x, left.y + 1));
    assert_eq!(
        app.view_state.left_pct, 40,
        "reaching a seam mid-drag must not start resizing"
    );
    assert_eq!(app.view_state.hover.get(), DragMode::Vertical);
    // Release returns to rest.
    app.handle_mouse(&mouse_up(2, left.y + 1));
    assert_eq!(app.view_state.hover.get(), DragMode::None);
}

#[test]
fn pane_shares_keep_minimums_at_extremes() {
    use ratatui::layout::Rect;
    let mut app = App::new().unwrap();
    app.layout.body_rect.set(Rect::new(0, 3, 100, 40));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    // Slam every divider against the bottom, then the top.
    app.view_state.questions_pct = 25;
    app.set_answers_from_y(3 + 30);
    assert_shares(&app);
    app.view_state.answers_pct = 30;
    app.set_questions_from_y(3 + 30);
    assert_shares(&app);
    app.set_answers_from_y(3);
    assert_shares(&app);
    assert_eq!(app.view_state.answers_pct, 10);
    // The clamped model still renders every pane at normal and
    // small sizes: no share collapses to zero rows.
    for (width, height) in [(100, 30), (60, 12)] {
        render_to_buffer(&app, width, height);
        for pane in [
            &app.layout.answers_rect,
            &app.layout.questions_rect,
            &app.layout.hex_rect,
        ] {
            assert!(
                pane.get().height >= 1,
                "{width}x{height}: slammed shares must still render every pane"
            );
        }
    }
}

#[test]
fn mouse_border_hit_test_prefers_seams() {
    use ratatui::layout::Rect;
    let app = App::new().unwrap();
    // Abutting panes: the two border cells form the grab zone.
    app.layout.left_rect.set(Rect::new(0, 3, 33, 30));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    app.layout.answers_rect.set(Rect::new(33, 3, 67, 10));
    app.layout.questions_rect.set(Rect::new(33, 13, 67, 14));
    app.layout.hex_rect.set(Rect::new(33, 27, 67, 6));
    // Either border cell grabs vertically.
    assert_eq!(app.divider_at(32, 5), DragMode::Vertical);
    assert_eq!(app.divider_at(33, 5), DragMode::Vertical);
    // Either border row grabs horizontally.
    assert_eq!(app.divider_at(40, 12), DragMode::HorizUpper);
    assert_eq!(app.divider_at(40, 13), DragMode::HorizUpper);
    assert_eq!(app.divider_at(40, 20), DragMode::None);
    assert_eq!(app.divider_at(40, 26), DragMode::HorizLower);
    assert_eq!(app.divider_at(40, 27), DragMode::HorizLower);
    // Interior cells belong to panes.
    assert_eq!(app.divider_at(10, 5), DragMode::None);
    assert_eq!(app.divider_at(40, 5), DragMode::None);
}

#[test]
fn mouse_down_on_border_starts_drag() {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    use ratatui::layout::Rect;
    let mut app = App::new().unwrap();
    app.layout.body_rect.set(Rect::new(0, 3, 100, 40));
    app.layout.left_rect.set(Rect::new(0, 3, 33, 37));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 37));
    app.layout.answers_rect.set(Rect::new(33, 3, 67, 12));
    app.layout.questions_rect.set(Rect::new(33, 15, 67, 12));
    app.layout.hex_rect.set(Rect::new(33, 27, 67, 13));
    // Right border cell of the Hosts pane starts a vertical drag.
    let down = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 32,
        row: 10,
        modifiers: KeyModifiers::empty(),
    };
    app.handle_mouse(&down);
    assert_eq!(app.view_state.drag, DragMode::Vertical);
}

#[test]
fn mouse_click_unfold_above_keeps_selection() {
    use ratatui::layout::Rect;
    let mut app = two_group_app();
    select_instance(&mut app, "Test");
    // Collapse the host above the selection, then click its header to
    // unfold: the inserted rows must not steal the cursor.
    app.collapsed_hosts.insert("shell.local".to_string());
    app.layout.left_rect.set(Rect::new(0, 3, 33, 30));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    let header = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Host { label } if label == "shell.local"))
        .expect("shell header");
    app.click_service_list(3 + 1 + header as u16);
    assert!(!app.is_host_collapsed("shell.local"));
    assert!(
        matches!(app.display_items().get(app.view_state.selected_display),
            Some(DisplayItem::Instance { index }) if app.services[*index].instance == "Test"),
        "selection must stay on Test, not jump into the unfolded host",
    );
    // Folding a host above the selection keeps it too.
    let header = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Host { label } if label == "shell.local"))
        .expect("shell header");
    app.click_service_list(3 + 1 + header as u16);
    assert!(app.is_host_collapsed("shell.local"));
    assert!(
        matches!(app.display_items().get(app.view_state.selected_display),
            Some(DisplayItem::Instance { index }) if app.services[*index].instance == "Test"),
    );
}

#[test]
fn mouse_wheel_moves_focused_pane_like_jk() {
    use crossterm::event::{KeyModifiers, MouseEvent, MouseEventKind};
    let mut app = two_group_app();
    let wheel = |kind| MouseEvent {
        kind,
        column: 0,
        row: 0,
        modifiers: KeyModifiers::empty(),
    };
    // Services: one notch moves the list selection one stop.
    app.view_state.focus = Focus::Services;
    let before = app.view_state.selected_display;
    app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
    assert_ne!(app.view_state.selected_display, before);
    app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
    assert_eq!(app.view_state.selected_display, before);
    // Answers: one notch moves the record cursor one row.
    service_with_txt(&mut app, "a=1; b=2");
    app.view_state.focus = Focus::Answers;
    let cursor = app.view_state.detail_selected;
    assert!(cursor > 0);
    app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
    assert_eq!(app.view_state.detail_selected, cursor - 1);
    app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.view_state.detail_selected, cursor);
    // Hex: one notch scrolls the dump one line.
    app.view_state.focus = Focus::Hex;
    app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.layout.hex_offset.get(), 1);
    app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
    assert_eq!(app.layout.hex_offset.get(), 0);
    // Diagnostics overlay owns the wheel while open.
    app.view_state.show_diagnostics = true;
    app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.layout.diagnostics_scroll.get(), 1);
    assert_eq!(app.view_state.detail_selected, cursor);
    // Horizontal wheel is ignored everywhere.
    app.view_state.show_diagnostics = false;
    app.handle_mouse(&wheel(MouseEventKind::ScrollLeft));
    app.handle_mouse(&wheel(MouseEventKind::ScrollRight));
    assert_eq!(app.layout.hex_offset.get(), 0);
    assert_eq!(app.view_state.detail_selected, cursor);
}

#[test]
fn mouse_wheel_moves_question_cursor() {
    use crossterm::event::{
        KeyCode, KeyEventKind, KeyEventState, KeyModifiers, MouseEvent, MouseEventKind,
    };
    let mut app = two_group_app();
    let plain = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    let wheel = |kind| MouseEvent {
        kind,
        column: 0,
        row: 0,
        modifiers: KeyModifiers::empty(),
    };
    let src: std::net::SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let sel_idx = match app.display_items().get(app.view_state.selected_display) {
        Some(DisplayItem::Instance { index }) => *index,
        _ => panic!("expected instance selected"),
    };
    let raws = app.services[sel_idx].ordered_answers().len();
    for _ in 0..2 {
        app.services[sel_idx].questions.push((
            "_http._tcp.local".to_string(),
            "PTR".to_string(),
            src,
            Instant::now(),
            Vec::new(),
        ));
    }
    app.handle_key(&plain(KeyCode::Tab));
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Questions);
    assert_eq!(app.view_state.detail_selected, raws);
    app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
    assert_eq!(app.view_state.detail_selected, raws + 1);
    app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
    assert_eq!(app.view_state.detail_selected, raws);
}

#[test]
fn mouse_click_selects_service_and_focuses() {
    use ratatui::layout::Rect;
    let mut app = two_group_app();
    app.view_state.focus = Focus::Answers;
    // Left pane shows: enum header, enum row, then host groups.
    let items = app.display_items();
    let first_instance = items
        .iter()
        .position(|it| matches!(it, DisplayItem::Instance { .. }))
        .expect("instance row");
    app.layout.list_offset.set(0);
    app.layout.left_rect.set(Rect::new(0, 3, 33, 30));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    app.layout.answers_rect.set(Rect::new(33, 3, 67, 10));
    app.layout.questions_rect.set(Rect::new(33, 13, 67, 10));
    app.layout.hex_rect.set(Rect::new(33, 23, 67, 10));
    let row = 3 + 1 + first_instance as u16;
    app.click_service_list(row);
    assert_eq!(app.view_state.focus, Focus::Services);
    assert_eq!(app.view_state.selected_display, first_instance);
}

#[test]
fn mouse_click_header_folds_host() {
    use ratatui::layout::Rect;
    let mut app = two_group_app();
    let header = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Host { .. }))
        .expect("host header");
    app.layout.list_offset.set(0);
    app.layout.left_rect.set(Rect::new(0, 3, 33, 30));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    app.layout.answers_rect.set(Rect::default());
    app.layout.questions_rect.set(Rect::default());
    app.layout.hex_rect.set(Rect::default());
    let row = 3 + 1 + header as u16;
    app.click_service_list(row);
    assert!(!app.collapsed_hosts.is_empty());
}

#[test]
fn mouse_click_answers_selects_record() {
    use ratatui::layout::Rect;
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    app.view_state.focus = Focus::Services;
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    app.layout.answers_rect.set(Rect::new(33, 3, 67, 20));
    app.layout.questions_rect.set(Rect::new(33, 24, 67, 8));
    app.layout.hex_rect.set(Rect::default());
    app.layout.detail_offset.set(0);
    // Table rows: 1 info row, then PTR/SRV/TXT in type order; the PTR
    // carries one finding child row (info ttl-mismatch).
    let info = 1;
    let raws = app
        .display_detail()
        .expect("detail")
        .ordered_answers()
        .len();
    assert!(raws >= 2);
    // A click on the finding child row selects its parent record.
    app.click_answers(3 + 2 + (info + 1) as u16);
    assert_eq!(app.view_state.focus, Focus::Answers);
    assert_eq!(app.view_state.detail_selected, 0);
    let row = 3 + 2 + (info + 2) as u16;
    app.click_answers(row);
    assert_eq!(app.view_state.detail_selected, 1);
}

#[test]
fn mouse_click_answers_child_selects_parent() {
    use ratatui::layout::Rect;
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    assert!(app.toggle_txt_expanded());
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    app.layout.answers_rect.set(Rect::new(33, 3, 67, 20));
    app.layout.questions_rect.set(Rect::new(33, 24, 67, 8));
    app.layout.hex_rect.set(Rect::default());
    app.layout.detail_offset.set(0);
    // Info(1) + PTR(1) + SRV(1) + TXT parent(1), then 2 child rows.
    // Clicking the first child must land on the TXT parent (index 2).
    let row = 3 + 2 + 4u16;
    app.click_answers(row);
    assert_eq!(app.view_state.detail_selected, 2);
}

/// Display positions of every selectable stop in order.
fn selectable_positions(app: &App) -> Vec<usize> {
    app.display_items()
        .iter()
        .enumerate()
        .filter(|(_, it)| app.is_selectable(it))
        .map(|(i, _)| i)
        .collect()
}

fn plain_key(code: KeyCode) -> KeyEvent {
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    }
}

fn left_click(app: &mut App, column: u16, row: u16) {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    app.handle_mouse(&MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    });
}

/// Screen row of the first line inside `area` that contains `needle`.
fn row_showing(buf: &ratatui::buffer::Buffer, area: ratatui::layout::Rect, needle: &str) -> u16 {
    rect_text(buf, area)
        .lines()
        .position(|l| l.contains(needle))
        .map(|i| area.y + i as u16)
        .unwrap_or_else(|| panic!("{needle} not shown"))
}

#[test]
fn clicking_a_question_selects_it() {
    let mut app = test_service_app();
    select_instance(&mut app, "Test");
    ask(&mut app, "Test._http._tcp.local.", querier(1));
    ask(&mut app, "Test._http._tcp.local.", querier(2));
    let raws = service_of(&app, "Test").ordered_answers().len();
    let buf = render_to_buffer(&app, 120, 40);
    let area = app.layout.questions_rect.get();
    // Newest first: querier 1's older question is on the second row.
    let second = row_showing(&buf, area, &querier(1).ip().to_string());

    left_click(&mut app, area.x + 2, second);
    assert_eq!(app.view_state.focus, Focus::Questions);
    assert_eq!(
        app.view_state.detail_selected,
        raws + 1,
        "the cursor lands on the clicked question"
    );

    // The header row selects nothing.
    let before = app.view_state.detail_selected;
    left_click(&mut app, area.x + 2, area.y + 1);
    assert_eq!(app.view_state.detail_selected, before);
}

/// Layout budget for the right stack: every pane keeps at least 10%
/// and leaves at least 10% for the hex pane.
fn assert_shares(app: &App) {
    assert!(
        app.view_state.answers_pct >= 10,
        "answers: {}",
        app.view_state.answers_pct
    );
    assert!(
        app.view_state.questions_pct >= 10,
        "questions: {}",
        app.view_state.questions_pct
    );
    assert!(
        app.view_state.answers_pct + app.view_state.questions_pct <= 90,
        "hex keeps >= 10: {}+{}",
        app.view_state.answers_pct,
        app.view_state.questions_pct,
    );
}

/// Lower-pane rect and moved share for a horizontal divider, by
/// mode: one dispatch shared by seam lookup and share reads.
fn seam_target(app: &App, mode: DragMode) -> (ratatui::layout::Rect, u16) {
    match mode {
        DragMode::HorizUpper => (app.layout.questions_rect.get(), app.view_state.answers_pct),
        _ => (app.layout.hex_rect.get(), app.view_state.questions_pct),
    }
}

#[test]
fn q_esc_and_ctrl_c_quit_also_from_the_diagnostics_overlay() {
    use crossterm::event::KeyModifiers;
    for (code, modifiers) in [
        (KeyCode::Char('q'), KeyModifiers::empty()),
        (KeyCode::Esc, KeyModifiers::empty()),
        (KeyCode::Char('c'), KeyModifiers::CONTROL),
    ] {
        let mut app = App::new().unwrap();
        press_with(&mut app, code, modifiers);
        assert!(!app.running, "{code:?} quits");
    }
    // In the overlay `Esc` only closes it; `q` still quits.
    let mut app = App::new().unwrap();
    app.handle_key(&plain_key(KeyCode::Char('d')));
    app.handle_key(&plain_key(KeyCode::Esc));
    assert!(app.running);
    app.handle_key(&plain_key(KeyCode::Char('d')));
    app.handle_key(&plain_key(KeyCode::Char('q')));
    assert!(!app.running);
    let mut app = App::new().unwrap();
    app.handle_key(&plain_key(KeyCode::Char('d')));
    press_with(
        &mut app,
        KeyCode::Char('c'),
        crossterm::event::KeyModifiers::CONTROL,
    );
    assert!(!app.running, "Ctrl+C quits from the overlay");
}

#[test]
fn arrow_and_page_keys_move_between_questions() {
    let mut app = test_service_app();
    select_instance(&mut app, "Test");
    for i in 1..=3 {
        ask(&mut app, "Test._http._tcp.local.", querier(i));
    }
    let raws = service_of(&app, "Test").ordered_answers().len();
    render_to_buffer(&app, 120, 40);
    // Tab to Answers, again to Questions: the cursor snaps to the first.
    app.handle_key(&plain_key(KeyCode::Tab));
    app.handle_key(&plain_key(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Questions);
    assert_eq!(app.view_state.detail_selected, raws);

    app.handle_key(&plain_key(KeyCode::Down));
    assert_eq!(app.view_state.detail_selected, raws + 1);
    app.handle_key(&plain_key(KeyCode::Up));
    assert_eq!(app.view_state.detail_selected, raws);
    app.handle_key(&plain_key(KeyCode::PageDown));
    assert_eq!(
        app.view_state.detail_selected,
        raws + 2,
        "a page down stops on the last question"
    );
    app.handle_key(&plain_key(KeyCode::PageUp));
    assert_eq!(
        app.view_state.detail_selected, raws,
        "a page up stops on the first question"
    );
}

#[test]
fn cursor_on_an_aged_out_question_parks_on_the_last_answer() {
    let mut app = test_service_app();
    select_instance(&mut app, "Test");
    ask(&mut app, "Test._http._tcp.local.", querier(1));
    ask(&mut app, "Test._http._tcp.local.", querier(2));
    let raws = service_of(&app, "Test").ordered_answers().len();
    render_to_buffer(&app, 120, 40);
    app.handle_key(&plain_key(KeyCode::Tab));
    app.handle_key(&plain_key(KeyCode::Tab));
    // Newest first: querier 1's question is the second one.
    app.handle_key(&plain_key(KeyCode::Down));
    assert_eq!(app.view_state.detail_selected, raws + 1);

    let expired = Instant::now()
        .checked_sub(QUESTION_WINDOW + Duration::from_secs(60))
        .expect("monotonic clock far enough from boot");
    for svc in &mut app.services {
        for q in &mut svc.questions {
            if q.2 == querier(1) {
                q.3 = expired;
            }
        }
    }
    app.evict_expired();
    app.clamp_selection();
    assert_eq!(
        app.view_state.detail_selected,
        raws - 1,
        "parked on the last answer, not on the row that moved up"
    );
}

#[test]
fn plus_folds_and_unfolds_the_enumeration_group() {
    let mut app = app_with_stale_enum_row();
    let is_enum_row = |it: &DisplayItem| matches!(it, DisplayItem::Enum { .. });
    let row = app
        .display_items()
        .iter()
        .position(is_enum_row)
        .expect("an enumeration row");
    app.view_state.selected_display = row;

    app.handle_key(&plain_key(KeyCode::Char('+')));
    assert!(
        !app.display_items().iter().any(is_enum_row),
        "folded: only the group header is left"
    );
    let header = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Host { label } if label == ENUM_HOST))
        .expect("enumeration header");
    assert_eq!(
        app.view_state.selected_display, header,
        "cursor on the header"
    );

    app.handle_key(&plain_key(KeyCode::Char('+')));
    assert!(
        app.display_items().iter().any(is_enum_row),
        "unfolded again"
    );
}
