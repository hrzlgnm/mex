// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

//! Manual refresh (#394): `r` on a `self` row in the Questions pane
//! sends that question once, now.

use super::*;
use crossterm::event::KeyCode;

/// A service whose PTR refresh already went out once, so the Questions
/// pane carries a `self` PTR row; the Questions pane is focused.
fn app_with_self_ptr_row() -> App {
    let mut app = due_query_setup();
    app.send_queries();
    // That scheduled send is more than a second old.
    backdate_transmit(&mut app, Duration::from_secs(2));
    select_instance(&mut app, "Test");
    render_to_buffer(&app, 120, 40);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view_state.focus, Focus::Questions);
    app
}

/// Move the Questions cursor (with keys) onto the first row matching
/// `pick`; panics when no row matches.
fn cursor_to_question(app: &mut App, pick: impl Fn(&str, &str, SocketAddr) -> bool) {
    press(app, KeyCode::Home);
    for _ in 0..64 {
        if let Some(DetailEntry::Question {
            name,
            rtype_str,
            source,
            ..
        }) = app.selected_detail_entry()
        {
            if pick(name, rtype_str, *source) {
                return;
            }
        }
        press(app, KeyCode::Down);
    }
    panic!("no matching question row");
}

fn cursor_to_self_ptr(app: &mut App) {
    cursor_to_question(app, |_, t, s| t == "PTR" && s == SELF_SOURCE);
}

fn backdate_transmit(app: &mut App, by: Duration) {
    let state = app
        .scheduler
        .query_history_mut()
        .get_mut(&("_http._tcp.local".to_string(), 12))
        .expect("PTR interest has a transmit");
    state.transmitted = state.transmitted.map(|t| t - by);
}

/// `r` never pops up a status message: its feedback is the row.
fn assert_no_popup(app: &App) {
    assert!(app.status_msg.is_none(), "{:?}", app.status_msg);
}

/// The Questions pane line of the `self` row for `name`.
fn self_row_line(app: &App, name: &str) -> String {
    let buf = render_to_buffer(app, 120, 40);
    rect_text(&buf, app.layout.questions_rect.get())
        .lines()
        .find(|l| l.contains(name) && l.contains("self"))
        .unwrap_or_else(|| panic!("no self row for {name}"))
        .to_string()
}

fn last_transmitted(app: &App) -> Option<Instant> {
    app.interest_summary("_http._tcp.local", 12)
        .last_transmitted_at
}

#[test]
fn r_on_self_row_sends_that_question_now() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    let before = last_transmitted(&app);
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 1);
    assert!(
        last_transmitted(&app) > before,
        "LAST moves to the manual send"
    );
    assert_no_popup(&app);
    let row = self_row_line(&app, "_http._tcp.local.");
    assert!(
        row.contains("0s manual"),
        "LAST names the manual send: {row}"
    );
}

#[test]
fn r_on_foreign_row_sends_nothing() {
    let mut app = app_with_self_ptr_row();
    app.ingest_event(&query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    ));
    cursor_to_question(&mut app, |_, _, s| s == remote_source());
    let before = last_transmitted(&app);
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 0);
    assert_eq!(last_transmitted(&app), before);
    assert_no_popup(&app);
}

#[test]
fn r_outside_questions_pane_does_nothing() {
    let mut app = app_with_self_ptr_row();
    for _ in 0..3 {
        press(&mut app, KeyCode::Tab);
        assert_ne!(app.view_state.focus, Focus::Questions);
        press(&mut app, KeyCode::Char('r'));
        assert_eq!(app.diagnostics.q_sent_manual, 0);
        assert!(app.status_msg.is_none(), "{:?}", app.status_msg);
    }
}

#[test]
fn r_while_transmission_held_sends_nothing() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    let before = last_transmitted(&app);
    app.query_tx.transmit().pin(false, false);
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 0);
    assert_eq!(last_transmitted(&app), before);
    assert_no_popup(&app);
}

#[test]
fn r_in_passive_mode_sends_nothing() {
    // Passive mode files no self rows; a foreign row stays inert too.
    let mut app = App::new_with(true, None).unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    app.ingest_event(&query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    ));
    select_instance(&mut app, "Test");
    render_to_buffer(&app, 120, 40);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    cursor_to_question(&mut app, |_, _, s| s == remote_source());
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 0);
    assert_no_popup(&app);
}

#[test]
fn r_sends_at_most_once_per_second_per_question() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    press(&mut app, KeyCode::Char('r'));
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 1, "key repeat is held back");
    assert_no_popup(&app);
    backdate_transmit(&mut app, Duration::from_millis(1001));
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 2);
}

#[test]
fn r_right_after_a_scheduled_send_is_held_back() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    let state = app
        .scheduler
        .query_history_mut()
        .get_mut(&("_http._tcp.local".to_string(), 12))
        .unwrap();
    state.transmitted = Some(Instant::now());
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 0);
}

#[test]
fn r_postpones_a_due_browse_query_and_keeps_the_refresh_timer() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    // The discovery stream for the same question is due right now.
    app.scheduler.continuous_mut().insert(
        ("_http._tcp.local".to_string(), 12),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(8),
            qname: "_http._tcp.local".to_string(),
        },
    );
    let refresh_before = app.interest_summary("_http._tcp.local", 12);
    let continuous_sent = app.diagnostics.q_sent_continuous;
    let refresh_sent = app.diagnostics.q_sent_refresh;
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 1);
    app.send_queries();
    assert_eq!(
        app.diagnostics.q_sent_continuous, continuous_sent,
        "no back-to-back duplicate of the manual query"
    );
    assert_eq!(app.diagnostics.q_sent_refresh, refresh_sent);
    let entry = &app.scheduler.continuous()[&("_http._tcp.local".to_string(), 12)];
    assert_eq!(entry.interval, Duration::from_secs(8), "backoff unchanged");
    let refresh_after = app.interest_summary("_http._tcp.local", 12);
    assert_eq!(
        app.scheduler.requeries()[&("_http._tcp.local".to_string(), 12)].1,
        1,
        "the manual send used no refresh attempt"
    );
    assert_eq!(refresh_after.timer, refresh_before.timer);
}

#[test]
fn r_starts_no_browse_stream_for_an_interest_without_one() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    let key = ("_http._tcp.local".to_string(), 12);
    app.scheduler.continuous_mut().remove(&key);
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 1);
    assert!(!app.scheduler.continuous().contains_key(&key));
}

#[test]
fn r_is_not_suppressed_by_an_overheard_identical_question() {
    let mut app = app_with_self_ptr_row();
    app.ingest_event(&query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    ));
    cursor_to_self_ptr(&mut app);
    let suppressed = app.diagnostics.suppressed_refresh + app.diagnostics.suppressed_continuous;
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(
        app.diagnostics.q_sent_manual, 1,
        "user intent wins over §7.3"
    );
    assert_eq!(
        app.diagnostics.suppressed_refresh + app.diagnostics.suppressed_continuous,
        suppressed
    );
}

#[test]
fn r_with_the_listener_gone_counts_nothing() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    let before = last_transmitted(&app);
    app.query_tx = browse::QueryTx::disconnected();
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 0);
    assert_eq!(last_transmitted(&app), before);
    assert_no_popup(&app);
    let row = self_row_line(&app, "_http._tcp.local.");
    assert!(!row.contains("manual"), "{row}");
}

#[test]
fn cursor_stays_on_the_row_after_r() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    press(&mut app, KeyCode::Char('r'));
    render_to_buffer(&app, 120, 40);
    press(&mut app, KeyCode::Char('r'));
    match app.selected_detail_entry() {
        Some(DetailEntry::Question {
            name,
            rtype_str,
            source,
            ..
        }) => {
            assert_eq!(name, "_http._tcp.local.");
            assert_eq!(rtype_str, "PTR");
            assert_eq!(*source, SELF_SOURCE);
        }
        _ => panic!("cursor left the self PTR row"),
    }
}

#[test]
fn r_on_the_enumeration_self_row_sends_the_enumeration_query() {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &enum_row("_http._tcp.local.", 4500, "192.168.1.3:5353", 0),
    );
    // The enumeration stream is due: its send files the self row.
    app.scheduler.continuous_mut().insert(
        ("_services._dns-sd._udp.local".to_string(), 12),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(2),
            qname: "_services._dns-sd._udp.local".to_string(),
        },
    );
    app.send_queries();
    let enum_pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Enum { .. }))
        .expect("enum row");
    app.view_state.selected_display = enum_pos;
    app.clamp_selection();
    let key = ("_services._dns-sd._udp.local".to_string(), 12);
    if let Some(state) = app.scheduler.query_history_mut().get_mut(&key) {
        state.transmitted = state.transmitted.map(|t| t - Duration::from_secs(2));
    }
    render_to_buffer(&app, 120, 40);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    cursor_to_self_ptr(&mut app);
    let ka_before = app.diagnostics.ka_sent;
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 1);
    let row = self_row_line(&app, "_services._dns-sd._udp.local.");
    assert!(row.contains("0s manual"), "{row}");
    assert_eq!(
        app.diagnostics.ka_sent - ka_before,
        1,
        "the fresh enumeration answer rides along as a known answer"
    );
}

#[test]
fn manual_sends_show_in_diagnostics_and_the_state_dump() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    press(&mut app, KeyCode::Char('r'));
    let rows = app.diagnostics_rows();
    let sent = &rows.iter().find(|(k, _)| k == "sent").expect("sent row").1;
    assert!(sent.contains("· 1 manual ·"), "{sent}");
    let dump = app.state_dump();
    assert_eq!(dump.diagnostics["q_sent_manual"], 1);
    let interest = dump
        .interests
        .iter()
        .find(|i| i.name == "_http._tcp.local" && i.rtype == 12)
        .expect("PTR interest dumped");
    assert_eq!(interest.last_origin.as_deref(), Some("manual"));
}

#[test]
fn header_hints_r_only_while_a_self_question_is_selected() {
    let header = |app: &App| {
        let buf = render_to_buffer(app, 200, 40);
        rect_text(&buf, ratatui::layout::Rect::new(0, 0, 200, 3))
    };
    let mut app = app_with_self_ptr_row();
    app.ingest_event(&query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    ));
    cursor_to_self_ptr(&mut app);
    assert!(header(&app).contains("[r] send"), "{}", header(&app));
    // Same pane, but a foreign question: `r` would do nothing.
    cursor_to_question(&mut app, |_, _, s| s == remote_source());
    assert!(!header(&app).contains("[r] send"), "{}", header(&app));
    cursor_to_self_ptr(&mut app);
    press(&mut app, KeyCode::Tab);
    assert!(!header(&app).contains("[r] send"), "{}", header(&app));
}

#[test]
fn a_later_scheduled_send_shows_transmitted_again() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    press(&mut app, KeyCode::Char('r'));
    let later = Instant::now() + Duration::from_millis(5);
    app.note_query("_http._tcp.local", 12, QueryOrigin::Transmitted, later);
    let row = self_row_line(&app, "_http._tcp.local.");
    assert!(row.contains("transmitted"), "{row}");
    assert!(!row.contains("manual"), "{row}");
}

#[test]
fn ctrl_r_and_alt_r_send_nothing() {
    use crossterm::event::KeyModifiers;
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    press_with(&mut app, KeyCode::Char('r'), KeyModifiers::CONTROL);
    press_with(&mut app, KeyCode::Char('r'), KeyModifiers::ALT);
    assert_eq!(app.diagnostics.q_sent_manual, 0);
}

#[test]
fn a_due_refresh_waits_out_the_spacing_after_r() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    // The PTR row's next refresh attempt is due right now.
    for state in app.scheduler.refresh_rows_mut().values_mut() {
        state.next_due = Instant::now() - Duration::from_millis(1);
    }
    let refresh_sent = app.diagnostics.q_sent_refresh;
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 1);
    app.send_queries();
    assert_eq!(
        app.diagnostics.q_sent_refresh, refresh_sent,
        "no refresh right on top of the manual query"
    );
    // Once the second has passed, the refresh goes out and keeps its
    // attempt.
    let state = app
        .scheduler
        .query_history_mut()
        .get_mut(&("_http._tcp.local".to_string(), 12))
        .unwrap();
    state.transmitted = state.transmitted.map(|t| t - Duration::from_millis(1100));
    state.manual = state.manual.map(|t| t - Duration::from_millis(1100));
    app.send_queries();
    assert_eq!(app.diagnostics.q_sent_refresh, refresh_sent + 1);
}

#[test]
fn r_consumes_an_overheard_question_so_the_next_send_is_not_suppressed() {
    let mut app = app_with_self_ptr_row();
    app.ingest_event(&query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    ));
    cursor_to_self_ptr(&mut app);
    press(&mut app, KeyCode::Char('r'));
    // The discovery stream comes due while the overheard question is
    // still inside its window.
    let key = ("_http._tcp.local".to_string(), 12);
    app.scheduler.continuous_mut().insert(
        key.clone(),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(8),
            qname: key.0.clone(),
        },
    );
    let continuous_sent = app.diagnostics.q_sent_continuous;
    app.send_queries();
    assert_eq!(app.diagnostics.suppressed_continuous, 0);
    assert_eq!(app.diagnostics.q_sent_continuous, continuous_sent + 1);
}

#[test]
fn r_on_an_nsec_denied_address_type_sends_nothing() {
    let mut app = knulp_app();
    app.route_own_question("knulp.local", 28, false);
    ingest(&mut app, &legacy_aaaa_denial());
    select_instance(&mut app, "iTunes_Ctrl");
    render_to_buffer(&app, 120, 40);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    cursor_to_question(&mut app, |_, t, s| t == "AAAA" && s == SELF_SOURCE);
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(
        app.diagnostics.q_sent_manual, 0,
        "the service drives no AAAA interest"
    );
}

#[test]
fn a_denial_for_the_old_host_does_not_block_the_new_target() {
    let mut app = knulp_app();
    // RFC form: _dacp says knulp.local has only A, so no AAAA.
    app.ingest_event(&packet(vec![
        srv_on_knulp(DACP),
        raw_record("knulp.local.", 47, "NSEC", "knulp.local. A", 120),
    ]));
    assert_eq!(
        app.address_denials
            .denied_types(&service_key("iTunes_Ctrl", "_dacp._tcp.local")),
        vec![(28, Some("knulp.local".to_string()))]
    );
    // _dacp moves to another host, which does have an AAAA interest.
    let mut srv = raw_record(DACP, 33, "SRV", "0 0 3689 other.local.", 120);
    srv.flush_bit = true;
    ingest(&mut app, &srv);
    // The host-scoped denial outlives the retarget (TTL only).
    assert!(!app
        .address_denials
        .denied_types(&service_key("iTunes_Ctrl", "_dacp._tcp.local"))
        .is_empty());
    app.route_own_question("other.local", 28, false);
    select_instance(&mut app, "iTunes_Ctrl");
    render_to_buffer(&app, 120, 40);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    cursor_to_question(&mut app, |n, t, s| {
        n == "other.local." && t == "AAAA" && s == SELF_SOURCE
    });
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(
        app.diagnostics.q_sent_manual, 1,
        "only knulp's AAAA is denied"
    );
    let row = self_row_line(&app, "other.local.");
    assert!(row.contains("0s manual"), "{row}");
}

#[test]
fn r_on_an_empty_questions_pane_sends_nothing() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    select_instance(&mut app, "Test");
    render_to_buffer(&app, 120, 40);
    press(&mut app, KeyCode::Tab);
    press(&mut app, KeyCode::Tab);
    assert_eq!(app.view_state.focus, Focus::Questions);
    assert!(
        !matches!(
            app.selected_detail_entry(),
            Some(DetailEntry::Question { .. })
        ),
        "no question rows"
    );
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 0);
    assert_no_popup(&app);
}

#[test]
fn r_leaves_a_browse_stream_that_is_already_due_later_alone() {
    let mut app = app_with_self_ptr_row();
    cursor_to_self_ptr(&mut app);
    let key = ("_http._tcp.local".to_string(), 12);
    let later = Instant::now() + Duration::from_secs(600);
    app.scheduler.continuous_mut().insert(
        key.clone(),
        ContinuousQuery {
            next_due: later,
            interval: Duration::from_secs(8),
            qname: key.0.clone(),
        },
    );
    press(&mut app, KeyCode::Char('r'));
    assert_eq!(app.diagnostics.q_sent_manual, 1);
    assert_eq!(app.scheduler.continuous()[&key].next_due, later);
}
