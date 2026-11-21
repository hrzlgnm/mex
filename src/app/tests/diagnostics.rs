// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;
use crate::app::rusage;

#[test]
fn diagnostics_hosts_exclude_enumeration_group() {
    let app = App::new().unwrap();
    let row = app
        .diagnostics_rows()
        .into_iter()
        .find(|(k, _)| k == "hosts")
        .expect("hosts row");
    assert_eq!(row.1, "0");
    let app = two_group_app();
    let row = app
        .diagnostics_rows()
        .into_iter()
        .find(|(k, _)| k == "hosts")
        .expect("hosts row");
    assert_eq!(row.1, "2");
}

#[test]
fn diagnostics_queriers_exclude_self() {
    let mut app = two_group_app();
    app.route_own_question("_http._tcp.local.", 12, false);
    let row = app
        .diagnostics_rows()
        .into_iter()
        .find(|(k, _)| k == "questions")
        .expect("questions row");
    assert!(
        row.1.starts_with("1 current (0 queriers)"),
        "got: {}",
        row.1
    );
}

#[test]
fn diagnostics_questions_count_one_shot_queriers() {
    let mut app = two_group_app();
    let stub: std::net::SocketAddr = "192.168.1.9:45678".parse().unwrap();
    app.ingest_event(&query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        vec![],
        stub,
    ));
    let row = app
        .diagnostics_rows()
        .into_iter()
        .find(|(k, _)| k == "questions")
        .expect("questions row");
    assert!(row.1.contains("(1 queriers, 1 one-shot)"), "got: {}", row.1);
}

#[test]
fn packet_diagnostics_count_by_type_and_iface() {
    let mut app = App::new().unwrap();
    let mut rec = ptr_record(120);
    rec.iface = "br0".to_string();
    rec.flush_bit = true;
    let ev = browse::Event {
        answers: vec![rec],
        questions: Vec::new(),
        query_kas: Vec::new(),
        rcode: Some(0),
        received_at: Instant::now(),
        raw_bytes: vec![0u8; 100],
        source: test_source(),
    };
    app.note_packet_diagnostics(&ev);
    assert_eq!(app.diagnostics.records_total, 1);
    assert_eq!(app.diagnostics.records_by_type.get(&12), Some(&1));
    assert_eq!(app.diagnostics.flush_seen, 1);
    assert_eq!(app.diagnostics.bytes_total, 100);
    assert_eq!(app.diagnostics.iface_rx.get("br0"), Some(&1));
    assert_eq!(app.diagnostics.source_rx.get(&test_source()), Some(&1));
    assert!(app.diagnostics.last_packet_at.is_some());
}

#[test]
fn packet_diagnostics_buckets_unmapped_link_by_index() {
    let mut app = App::new().unwrap();
    let mut rec = ptr_record(120);
    rec.iface = String::new();
    rec.ifindex = 7;
    app.note_packet_diagnostics(&event_for(&rec));
    assert_eq!(app.diagnostics.iface_rx.get("if#7"), Some(&1));
    assert!(
        !app.diagnostics.iface_rx.contains_key(""),
        "no opaque empty bucket"
    );
    assert_eq!(App::link_key("", 0), "if#0");
    assert_eq!(App::link_key("br0", 2), "br0");
}

#[test]
fn packet_diagnostics_counts_goodbyes_and_qu() {
    let mut app = App::new().unwrap();
    let ev = browse::Event {
        answers: vec![ptr_record(0)],
        questions: vec![browse::RawRecord {
            name: "_http._tcp.local.".to_string(),
            owner_labels: vec![b"_http".to_vec(), b"_tcp".to_vec(), b"local".to_vec()],
            ptr_target_labels: None,
            rtype: 12,
            rtype_str: "PTR".to_string(),
            flush_bit: false,
            qu: true,
            invalid_utf8: false,
            ttl: 0,
            rdata: String::new(),
            wire: Vec::new(),
            source: remote_source(),
            iface: String::new(),
            ifindex: 0,
            dst_is_multicast: true,
            section: browse::RecordSection::Question,
            received_at: Instant::now(),
            trigger: None,
        }],
        query_kas: vec![ptr_record(120)],
        rcode: Some(0),
        received_at: Instant::now(),
        raw_bytes: Vec::new(),
        source: remote_source(),
    };
    app.note_packet_diagnostics(&ev);
    assert_eq!(app.diagnostics.goodbyes_seen, 1);
    assert_eq!(app.diagnostics.questions_total, 1);
    assert_eq!(app.diagnostics.qu_questions_seen, 1);
    assert_eq!(app.diagnostics.qm_questions_seen, 0);
    assert_eq!(app.diagnostics.kas_seen, 1);
}

#[test]
fn diagnostics_toggle_and_scroll_keys() {
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    let key = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    assert!(!app.view_state.show_diagnostics);
    app.handle_key(&key(KeyCode::Char('d')));
    assert!(app.view_state.show_diagnostics);
    assert_eq!(app.layout.diagnostics_scroll.get(), 0);
    assert_eq!(app.layout.diagnostics_hscroll.get(), 0);
    app.handle_key(&key(KeyCode::Char('j')));
    assert_eq!(app.layout.diagnostics_scroll.get(), 1);
    app.handle_key(&key(KeyCode::Char('k')));
    assert_eq!(app.layout.diagnostics_scroll.get(), 0);
    // Uppercase reports the same intent.
    app.handle_key(&key(KeyCode::Char('J')));
    assert_eq!(app.layout.diagnostics_scroll.get(), 1);
    app.handle_key(&key(KeyCode::Char('K')));
    assert_eq!(app.layout.diagnostics_scroll.get(), 0);
    // Horizontal pan: h/l and arrows move one char, Ctrl jumps ten,
    // `0` jumps back. The key column stays frozen (no vertical move).
    app.handle_key(&key(KeyCode::Char('l')));
    assert_eq!(app.layout.diagnostics_hscroll.get(), 1);
    app.handle_key(&key(KeyCode::Right));
    assert_eq!(app.layout.diagnostics_hscroll.get(), 2);
    app.handle_key(&key(KeyCode::Char('h')));
    assert_eq!(app.layout.diagnostics_hscroll.get(), 1);
    app.handle_key(&key(KeyCode::Left));
    assert_eq!(app.layout.diagnostics_hscroll.get(), 0);
    app.handle_key(&key(KeyCode::Char('h')));
    assert_eq!(app.layout.diagnostics_hscroll.get(), 0);
    let ctrl = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(&ctrl(KeyCode::Char('l')));
    assert_eq!(app.layout.diagnostics_hscroll.get(), 10);
    app.handle_key(&ctrl(KeyCode::Right));
    assert_eq!(app.layout.diagnostics_hscroll.get(), 20);
    app.handle_key(&key(KeyCode::Char('0')));
    assert_eq!(app.layout.diagnostics_hscroll.get(), 0);
    assert_eq!(app.layout.diagnostics_scroll.get(), 0);
    app.handle_key(&key(KeyCode::Char('k')));
    assert_eq!(app.layout.diagnostics_scroll.get(), 0);
    // Tab must not escape the overlay.
    app.handle_key(&key(KeyCode::Tab));
    assert!(app.view_state.show_diagnostics);
    assert_eq!(app.view_state.focus, Focus::Services);
    app.handle_key(&key(KeyCode::Esc));
    assert!(!app.view_state.show_diagnostics);
}

#[test]
fn diagnostics_rows_has_all_sections() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let rows = app.diagnostics_rows();
    // mex's own cost sits between the network sections and the
    // anomalies summary. Nothing measurable — Windows, or a failed
    // rusage read (a supported degrade) — means no section at all,
    // so the expectations follow the live sample instead of
    // assuming it.
    let process = rusage::rows(&rusage::sample());
    let mut headers = vec!["Session", "Discovery", "Queries", "Links"];
    if !process.is_empty() {
        headers.push("Process");
    }
    headers.push("Anomalies");
    let shown: Vec<&str> = rows
        .iter()
        .filter(|(_, v)| v.is_empty())
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(shown, headers);
    assert!(rows.iter().any(|(k, _)| k == "packets"));
    assert!(rows.iter().any(|(k, _)| k == "sent"));
    assert!(rows.iter().any(|(k, _)| k == "usable v4"));
    if !process.is_empty() {
        for key in ["cpu", "memory", "page faults", "ctx switches"] {
            assert!(
                rows.iter().any(|(k, _)| k == key),
                "missing Process row {key}"
            );
        }
    }
}

#[test]
fn diagnostics_service_counters() {
    let mut app = App::new().unwrap();
    assert_eq!(app.diagnostics.services_seen_total, 0);
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    assert_eq!(app.diagnostics.services_seen_total, 1);
    assert_eq!(app.diagnostics.services_expired_total, 0);
    // Goodbye + grace expiry removes the service.
    ingest(&mut app, &ptr_record(0));
    for svc in &mut app.services {
        svc.last_seen = Instant::now() - Duration::from_secs(300);
    }
    app.evict_expired();
    assert!(app.services.is_empty());
    assert_eq!(app.diagnostics.services_expired_total, 1);
}

#[test]
fn diagnostics_suppression_counter() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let ckey = ("_http._tcp.local".to_string(), 12);
    app.scheduler.continuous_mut().insert(
        ckey.clone(),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(2),
            qname: "_http._tcp.local".to_string(),
        },
    );
    let ev = query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    app.poll_continuous();
    assert_eq!(app.diagnostics.suppressed_continuous, 1);
    assert_eq!(app.diagnostics.q_sent_continuous, 0);
}

#[test]
fn diagnostics_offlink_row_counts_refusals() {
    let app = App::new().unwrap();
    let rows = app.diagnostics_rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k == "refused off-link")
        .expect("refused row");
    assert_eq!(value, "0 total");
    app.drop_stats.note("203.0.113.9:5353".parse().unwrap());
    let rows = app.diagnostics_rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k == "refused off-link")
        .expect("refused row");
    assert!(value.contains("1 total"), "got: {value}");
    assert!(value.contains("203.0.113.9:5353"), "got: {value}");
}

#[test]
fn interface_selection_is_stored_and_shown_in_diagnostics() {
    use std::collections::HashSet;
    let sel = HashSet::from(["br0".to_string()]);
    let app = App::new_with(false, Some(sel)).unwrap();
    let rows = app.diagnostics_rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k == "selected")
        .expect("selected row");
    assert_eq!(value, "br0");
    // No selection: no row, default behavior unchanged.
    let app = App::new().unwrap();
    assert!(app.diagnostics_rows().iter().all(|(k, _)| k != "selected"));
}

#[test]
fn diagnostics_suppression_row_shows_recency() {
    let mut app = App::new().unwrap();
    app.diagnostics.suppressed_continuous = 2;
    app.diagnostics.suppressed_times.push_back(Instant::now());
    app.diagnostics
        .suppressed_times
        .push_back(Instant::now() - Duration::from_secs(120));
    let rows = app.diagnostics_rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k == "suppressed queries")
        .expect("suppression row");
    assert!(value.contains("2 total"), "got: {value}");
    assert!(value.contains("1 last 60s"), "got: {value}");
}

#[test]
fn diagnostics_has_no_flickering_overheard_rows() {
    let mut app = App::new().unwrap();
    // A live overheard QM question must not sprout short-lived rows:
    // suppression context lives in the counter row (total + last
    // 60s), not in a feed of 2s-lifetime entries.
    let ev = query_event(
        "_http._tcp.local.",
        12,
        "PTR",
        false,
        Vec::new(),
        remote_source(),
    );
    app.ingest_event(&ev);
    assert_eq!(app.scheduler.overheard().len(), 1);
    let rows = app.diagnostics_rows();
    assert!(
        rows.iter()
            .all(|(k, _)| !k.starts_with("heard ") && k != "overheard now"),
        "no per-entry overheard rows"
    );
    assert!(
        rows.iter().any(|(k, _)| k == "suppressed queries"),
        "counter row carries the context"
    );
}

#[test]
fn diagnostics_overlay_suppresses_resize_hover() {
    use crossterm::event::{
        KeyCode, KeyEventKind, KeyEventState, KeyModifiers, MouseEvent, MouseEventKind,
    };
    use ratatui::layout::Rect;
    let mut app = App::new().unwrap();
    app.layout.left_rect.set(Rect::new(0, 3, 33, 30));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    app.layout.answers_rect.set(Rect::new(33, 3, 67, 10));
    app.layout.questions_rect.set(Rect::new(33, 13, 67, 8));
    app.layout.hex_rect.set(Rect::new(33, 21, 67, 12));
    let moved = MouseEvent {
        kind: MouseEventKind::Moved,
        column: 32,
        row: 5,
        modifiers: KeyModifiers::empty(),
    };
    app.handle_mouse(&moved);
    assert_eq!(app.view_state.hover.get(), DragMode::Vertical);
    // Opening the overlay clears resize state...
    let d = KeyEvent {
        code: KeyCode::Char('d'),
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(&d);
    assert!(app.view_state.show_diagnostics);
    assert_eq!(app.view_state.drag, DragMode::None);
    assert_eq!(app.view_state.hover.get(), DragMode::None);
    // ...and motion over a seam while open stays inert.
    app.handle_mouse(&moved);
    assert_eq!(app.view_state.hover.get(), DragMode::None);
    app.handle_mouse(&mouse_down(32, 5));
    assert_eq!(app.view_state.drag, DragMode::None);
    // A release while the overlay is open is inert too: no resize
    // state may resurface behind it.
    app.handle_mouse(&mouse_up(32, 5));
    assert_eq!(app.view_state.drag, DragMode::None);
    assert_eq!(
        app.view_state.hover.get(),
        DragMode::None,
        "release behind the overlay must not set the hover glow"
    );
    // Closing restores hover tracking; nothing resurfaces before the
    // next motion event.
    app.handle_key(&d);
    assert!(!app.view_state.show_diagnostics);
    assert_eq!(app.view_state.hover.get(), DragMode::None);
    app.handle_mouse(&moved);
    assert_eq!(app.view_state.hover.get(), DragMode::Vertical);
}

#[test]
fn per_source_counters_stay_bounded_and_keep_the_top_talker() {
    // Spoofed or churning source addresses must not grow the per-source
    // map without bound; the overlay shows only the top talkers.
    let mut m = DiagnosticsCounters::default();
    let busy: SocketAddr = "192.168.1.2:5353".parse().unwrap();
    for _ in 0..50 {
        m.count_source(busy);
    }
    for i in 0..10_000u32 {
        let src = SocketAddr::from(([10, (i >> 16) as u8, (i >> 8) as u8, i as u8], 5353));
        m.count_source(src);
    }
    assert!(m.source_rx.len() <= SOURCE_RX_CAP);
    assert_eq!(m.source_rx.get(&busy), Some(&50));
}

#[test]
fn diagnostics_describe_received_traffic() {
    let mut app = App::new().unwrap();
    assert_eq!(diagnostics_value(&app, "last packet"), "—");
    let on_eth0 = |mut rec: browse::RawRecord| {
        rec.iface = "eth0".to_string();
        rec
    };
    // One response: PTR, SRV (flush bit) and an out-of-scope MX.
    let mut response = packet(vec![
        on_eth0(ptr_record(120)),
        on_eth0(srv_record(120)),
        on_eth0(raw_record("Test.local.", 15, "MX", "10 mx.local.", 120)),
    ]);
    response.raw_bytes = vec![0; 300];
    ingest_packet(&mut app, response);
    // One QM question from the same responder.
    let mut ask = query_event("_http._tcp.local.", 12, "PTR", false, vec![], test_source());
    ask.questions[0].iface = "eth0".to_string();
    ingest_packet(&mut app, ask);

    assert!(
        diagnostics_value(&app, "last packet").ends_with(" ago"),
        "a packet arrived"
    );
    assert!(diagnostics_value(&app, "answers ever").ends_with("other 1)"));
    assert!(diagnostics_value(&app, "flush-bit / goodbyes").starts_with("33% flush"));
    assert!(diagnostics_value(&app, "questions").contains("(0 QU / 1 QM)"));
    assert_eq!(diagnostics_value(&app, "rx eth0"), "2");
    assert_eq!(
        diagnostics_value(&app, &format!("talker {}", test_source())),
        "2 pkts"
    );
}

#[test]
fn diagnostics_summarize_discovery_and_refresh_schedules() {
    let mut app = App::new().unwrap();
    assert_eq!(
        diagnostics_value(&app, "continuous interests"),
        "0 · next in — · no interests"
    );
    assert_eq!(
        diagnostics_value(&app, "requeries"),
        "0 pending · 0 overdue · none unanswered"
    );

    let now = Instant::now();
    for (name, interval, overdue) in [
        ("_a._tcp.local", 2, true),
        ("_b._tcp.local", 2, false),
        ("_c._tcp.local", 180, false),
        ("_d._tcp.local", 7200, false),
    ] {
        app.scheduler.continuous_mut().insert(
            (name.to_string(), 12),
            ContinuousQuery {
                next_due: if overdue {
                    now - Duration::from_secs(1)
                } else {
                    now + Duration::from_secs(interval)
                },
                interval: Duration::from_secs(interval),
                qname: name.to_string(),
            },
        );
    }
    // Discovery groups interests by interval (shortest first) and is
    // due now for the overdue one.
    assert_eq!(
        diagnostics_value(&app, "continuous interests"),
        "4 · next in 0ms · 2s×2 3m×1 1h×1"
    );

    for (name, due_in, misses) in [("a.local", -1, 1), ("b.local", 60, 2), ("c.local", -1, 4)] {
        let due = if due_in < 0 {
            now - Duration::from_secs(1)
        } else {
            now + Duration::from_secs(due_in as u64)
        };
        app.scheduler
            .requeries_mut()
            .insert((name.to_string(), 1), (due, misses));
    }
    assert_eq!(
        diagnostics_value(&app, "requeries"),
        "3 pending · 2 overdue · miss×1:1 ×2:1 ×3:0 ×4:1"
    );
}

#[test]
fn diagnostics_split_current_answers_by_liveness() {
    let mut app = test_service_app();
    assert_eq!(
        diagnostics_value(&app, "answers current"),
        "2 live, 0 expired, 0 goodbye",
        "the fixture's PTR and SRV"
    );
    // The SRV outlives its TTL; the PTR is withdrawn by a goodbye.
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 33 {
                rec.received_at = Instant::now() - Duration::from_secs(121);
            }
        }
    }
    ingest(&mut app, &ptr_record(0));
    assert_eq!(
        diagnostics_value(&app, "answers current"),
        "0 live, 1 expired, 1 goodbye"
    );
}

#[test]
fn diagnostics_overlay_opens_with_d_and_closes_with_esc() {
    use crossterm::event::KeyCode;
    let mut app = two_group_app();
    let closed = screen(&app, 100, 40);
    assert!(!closed.iter().any(|l| l.contains("KEY")));

    press(&mut app, KeyCode::Char('d'));
    let open = screen(&app, 100, 40);
    assert!(
        open.iter().any(|l| l.contains(" Diagnostics (d/Esc close")),
        "overlay title shown"
    );
    assert!(open
        .iter()
        .any(|l| l.contains("KEY") && l.contains("VALUE")));
    assert!(open.iter().any(|l| l.contains("Session")), "first section");
    assert!(shows_row(&open, "hosts", "2"), "live state in the table");

    press(&mut app, KeyCode::Esc);
    let closed = screen(&app, 100, 40);
    assert!(!closed.iter().any(|l| l.contains("KEY")), "Esc closes");
}

#[test]
fn diagnostics_overlay_scrolls_to_the_ends_and_by_pages() {
    use crossterm::event::KeyCode;
    // 20 rows leave the overlay far fewer lines than it has rows.
    let mut app = two_group_app();
    press(&mut app, KeyCode::Char('d'));
    let last_key = app.diagnostics_rows().last().expect("rows").0.clone();
    let first_page = screen(&app, 100, 20);
    assert!(first_page.iter().any(|l| l.contains("uptime")));
    assert!(!first_page.iter().any(|l| l.contains(&last_key)));

    press(&mut app, KeyCode::End);
    let end = screen(&app, 100, 20);
    assert!(
        end.iter().any(|l| l.contains(&last_key)),
        "End shows the last row"
    );
    assert!(!end.iter().any(|l| l.contains("uptime")));

    // On the first page, by rows: `uptime`'s value ticks between frames.
    let on_first_page = |lines: &[String]| {
        lines.iter().any(|l| l.contains("uptime")) && !lines.iter().any(|l| l.contains(&last_key))
    };

    press(&mut app, KeyCode::Home);
    assert!(
        on_first_page(&screen(&app, 100, 20)),
        "Home returns to the top"
    );

    press(&mut app, KeyCode::PageDown);
    let paged = screen(&app, 100, 20);
    assert!(
        !paged.iter().any(|l| l.contains("uptime")),
        "a page down leaves the first page"
    );
    assert!(
        !paged.iter().any(|l| l.contains(&last_key)),
        "not to the end"
    );
    press(&mut app, KeyCode::PageUp);
    assert!(
        on_first_page(&screen(&app, 100, 20)),
        "a page up comes back"
    );
}

#[test]
fn diagnostics_overlay_pans_long_values_and_resets() {
    use crossterm::event::{KeyCode, KeyModifiers};
    // 40 columns leave values only a few cells; the key column stays put.
    let mut app = two_group_app();
    press(&mut app, KeyCode::Char('d'));
    let value = diagnostics_value(&app, "bytes");
    assert!(value.chars().count() > 12, "long enough to pan: {value}");
    // `shows_row` skips the gap after the key, so match from the first
    // visible non-blank character.
    let shown_from = |skip: usize| {
        let rest: String = value.chars().skip(skip).collect();
        rest.trim_start().chars().take(4).collect::<String>()
    };
    // The positions compared below must look different on screen.
    assert_ne!(shown_from(0), shown_from(4));
    assert_ne!(shown_from(4), shown_from(5));
    assert_ne!(shown_from(4), shown_from(14));
    assert!(shows_row(&screen(&app, 40, 40), "bytes", &shown_from(0)));

    for _ in 0..4 {
        press(&mut app, KeyCode::Char('l'));
    }
    press(&mut app, KeyCode::Right);
    assert!(
        shows_row(&screen(&app, 40, 40), "bytes", &shown_from(5)),
        "five steps right"
    );
    press(&mut app, KeyCode::Char('h'));
    assert!(
        shows_row(&screen(&app, 40, 40), "bytes", &shown_from(4)),
        "one step back"
    );

    press_with(&mut app, KeyCode::Char('l'), KeyModifiers::CONTROL);
    assert!(
        shows_row(&screen(&app, 40, 40), "bytes", &shown_from(14)),
        "Ctrl pans ten right"
    );
    press_with(&mut app, KeyCode::Left, KeyModifiers::CONTROL);
    assert!(
        shows_row(&screen(&app, 40, 40), "bytes", &shown_from(4)),
        "Ctrl pans ten and back"
    );

    press(&mut app, KeyCode::Char('0'));
    assert!(
        shows_row(&screen(&app, 40, 40), "bytes", &shown_from(0)),
        "0 resets the pan"
    );
}
