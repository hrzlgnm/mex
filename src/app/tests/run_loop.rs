// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! The run loops' per-pass work and event dispatch; the loops
//! themselves only add terminal I/O, sleeping and drawing.

use super::*;
use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};

fn key(code: KeyCode, modifiers: KeyModifiers, kind: KeyEventKind) -> Event {
    Event::Key(KeyEvent {
        code,
        modifiers,
        kind,
        state: KeyEventState::empty(),
    })
}

fn press(code: KeyCode) -> Event {
    key(code, KeyModifiers::empty(), KeyEventKind::Press)
}

#[test]
fn tick_reports_whether_packets_arrived() {
    let mut app = App::new().unwrap();
    let (tx, rx) = mpsc::channel();
    app.rx = rx;
    assert!(!app.tick(), "nothing arrived");
    tx.send(event_for(&ptr_record(120))).unwrap();
    assert!(app.tick(), "a packet arrived");
    assert_eq!(app.packet_count, 1);
    assert!(!app.tick(), "and nothing since");
}

#[test]
fn only_key_presses_act() {
    let mut app = App::new().unwrap();
    for kind in [KeyEventKind::Release, KeyEventKind::Repeat] {
        let generation = app.state_gen;
        let action =
            app.handle_terminal_event(key(KeyCode::Char('q'), KeyModifiers::empty(), kind));
        assert_eq!(action, TerminalAction::Handled);
        assert!(app.running, "{kind:?} of q does not quit");
        assert_eq!(app.state_gen, generation, "{kind:?} changes nothing");
    }
    assert_eq!(
        app.handle_terminal_event(press(KeyCode::Char('q'))),
        TerminalAction::Handled
    );
    assert!(!app.running, "a q press quits");
}

#[cfg(unix)]
#[test]
fn ctrl_z_asks_the_loop_to_suspend_before_key_handling() {
    let mut app = App::new().unwrap();
    let generation = app.state_gen;
    let ctrl_z = key(
        KeyCode::Char('z'),
        KeyModifiers::CONTROL,
        KeyEventKind::Press,
    );
    assert_eq!(app.handle_terminal_event(ctrl_z), TerminalAction::Suspend);
    assert_eq!(app.state_gen, generation, "not passed on as a key");
    assert!(app.running);
}

#[test]
fn mouse_and_resize_touch_the_view_other_events_do_not() {
    use crossterm::event::{MouseEvent, MouseEventKind};
    let mut app = App::new().unwrap();
    let mut generation = app.state_gen;
    let mouse = Event::Mouse(MouseEvent {
        kind: MouseEventKind::Moved,
        column: 0,
        row: 0,
        modifiers: KeyModifiers::empty(),
    });
    for event in [mouse, Event::Resize(80, 24)] {
        assert_eq!(app.handle_terminal_event(event), TerminalAction::Handled);
        assert_ne!(app.state_gen, generation, "touched");
        generation = app.state_gen;
    }
    assert_eq!(
        app.handle_terminal_event(Event::FocusGained),
        TerminalAction::Handled
    );
    assert_eq!(app.state_gen, generation, "focus changes nothing shown");
}

#[test]
fn redraw_waits_for_a_change_or_the_next_second() {
    let mut gate = RedrawGate::default();
    assert!(gate.due(0), "the first pass draws");
    gate.drawn(0);
    assert!(!gate.due(0), "idle within the same second");
    assert!(gate.due(1), "the clock ticked over");
    gate.drawn(1);
    gate.mark();
    assert!(gate.due(1), "something changed");
}

#[test]
fn headless_progress_once_per_ten_packets() {
    // The headless loop ticks every 50 ms: a count resting on a
    // multiple of ten logs once, and a batch jumping past one still
    // logs.
    let mut app = App::new().unwrap();
    let mut logged = 0;
    assert_eq!(app.headless_progress(&mut logged), None, "no packets yet");
    app.packet_count = 9;
    assert_eq!(app.headless_progress(&mut logged), None);
    app.packet_count = 10;
    assert_eq!(
        app.headless_progress(&mut logged).as_deref(),
        Some("mex: 10 packets, 0 services seen")
    );
    assert_eq!(app.headless_progress(&mut logged), None, "idle tick");
    app.packet_count = 19;
    assert_eq!(app.headless_progress(&mut logged), None);
    app.packet_count = 23;
    assert_eq!(
        app.headless_progress(&mut logged).as_deref(),
        Some("mex: 23 packets, 0 services seen"),
        "a batch jumped past 20"
    );
    assert_eq!(app.headless_progress(&mut logged), None);
}

#[test]
fn log_failures_show_in_the_status_line() {
    let mut app = App::new().unwrap();
    app.show_status("log file: disk full".to_string());
    assert_eq!(
        app.status_msg.as_ref().map(|(m, _)| m.as_str()),
        Some("log file: disk full")
    );
}
