use super::*;

#[test]
fn metrics_hosts_exclude_enumeration_group() {
    let app = App::new().unwrap();
    let row = app
        .metrics_rows()
        .into_iter()
        .find(|(k, _)| k == "hosts")
        .expect("hosts row");
    assert_eq!(row.1, "0");
    let app = two_group_app();
    let row = app
        .metrics_rows()
        .into_iter()
        .find(|(k, _)| k == "hosts")
        .expect("hosts row");
    assert_eq!(row.1, "2");
}

#[test]
fn metrics_queriers_exclude_self() {
    let mut app = two_group_app();
    app.route_own_question("_http._tcp.local.", 12, false);
    let row = app
        .metrics_rows()
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
fn metrics_questions_count_one_shot_queriers() {
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
        .metrics_rows()
        .into_iter()
        .find(|(k, _)| k == "questions")
        .expect("questions row");
    assert!(row.1.contains("(1 queriers, 1 one-shot)"), "got: {}", row.1);
}

#[test]
fn packet_metrics_count_by_type_and_iface() {
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
    app.note_packet_metrics(&ev);
    assert_eq!(app.metrics.records_total, 1);
    assert_eq!(app.metrics.records_by_type.get(&12), Some(&1));
    assert_eq!(app.metrics.flush_seen, 1);
    assert_eq!(app.metrics.bytes_total, 100);
    assert_eq!(app.metrics.iface_rx.get("br0"), Some(&1));
    assert_eq!(app.metrics.source_rx.get(&test_source()), Some(&1));
    assert!(app.metrics.last_packet_at.is_some());
}

#[test]
fn packet_metrics_buckets_unmapped_link_by_index() {
    let mut app = App::new().unwrap();
    let mut rec = ptr_record(120);
    rec.iface = String::new();
    rec.ifindex = 7;
    app.note_packet_metrics(&event_for(&rec));
    assert_eq!(app.metrics.iface_rx.get("if#7"), Some(&1));
    assert!(
        !app.metrics.iface_rx.contains_key(""),
        "no opaque empty bucket"
    );
    assert_eq!(App::link_key("", 0), "if#0");
    assert_eq!(App::link_key("br0", 2), "br0");
}

#[test]
fn packet_metrics_counts_goodbyes_and_qu() {
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
    app.note_packet_metrics(&ev);
    assert_eq!(app.metrics.goodbyes_seen, 1);
    assert_eq!(app.metrics.questions_total, 1);
    assert_eq!(app.metrics.qu_questions_seen, 1);
    assert_eq!(app.metrics.qm_questions_seen, 0);
    assert_eq!(app.metrics.kas_seen, 1);
}

#[test]
fn metrics_toggle_and_scroll_keys() {
    use crossterm::event::{KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = App::new().unwrap();
    let key = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    assert!(!app.show_metrics);
    app.handle_key(&key(KeyCode::Char('m')));
    assert!(app.show_metrics);
    assert_eq!(app.layout.metrics_scroll.get(), 0);
    assert_eq!(app.layout.metrics_hscroll.get(), 0);
    app.handle_key(&key(KeyCode::Char('j')));
    assert_eq!(app.layout.metrics_scroll.get(), 1);
    app.handle_key(&key(KeyCode::Char('k')));
    assert_eq!(app.layout.metrics_scroll.get(), 0);
    // Uppercase reports the same intent.
    app.handle_key(&key(KeyCode::Char('J')));
    assert_eq!(app.layout.metrics_scroll.get(), 1);
    app.handle_key(&key(KeyCode::Char('K')));
    assert_eq!(app.layout.metrics_scroll.get(), 0);
    // Horizontal pan: h/l and arrows move one char, Ctrl jumps ten,
    // `0` jumps back. The key column stays frozen (no vertical move).
    app.handle_key(&key(KeyCode::Char('l')));
    assert_eq!(app.layout.metrics_hscroll.get(), 1);
    app.handle_key(&key(KeyCode::Right));
    assert_eq!(app.layout.metrics_hscroll.get(), 2);
    app.handle_key(&key(KeyCode::Char('h')));
    assert_eq!(app.layout.metrics_hscroll.get(), 1);
    app.handle_key(&key(KeyCode::Left));
    assert_eq!(app.layout.metrics_hscroll.get(), 0);
    app.handle_key(&key(KeyCode::Char('h')));
    assert_eq!(app.layout.metrics_hscroll.get(), 0);
    let ctrl = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::CONTROL,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(&ctrl(KeyCode::Char('l')));
    assert_eq!(app.layout.metrics_hscroll.get(), 10);
    app.handle_key(&ctrl(KeyCode::Right));
    assert_eq!(app.layout.metrics_hscroll.get(), 20);
    app.handle_key(&key(KeyCode::Char('0')));
    assert_eq!(app.layout.metrics_hscroll.get(), 0);
    assert_eq!(app.layout.metrics_scroll.get(), 0);
    app.handle_key(&key(KeyCode::Char('k')));
    assert_eq!(app.layout.metrics_scroll.get(), 0);
    // Tab must not escape the overlay.
    app.handle_key(&key(KeyCode::Tab));
    assert!(app.show_metrics);
    assert_eq!(app.focus, Focus::Services);
    app.handle_key(&key(KeyCode::Esc));
    assert!(!app.show_metrics);
}

#[test]
fn metrics_rows_has_all_sections() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let rows = app.metrics_rows();
    let headers: Vec<&str> = rows
        .iter()
        .filter(|(_, v)| v.is_empty())
        .map(|(k, _)| k.as_str())
        .collect();
    assert_eq!(
        headers,
        vec!["Session", "Discovery", "Queries", "Links", "Anomalies"]
    );
    assert!(rows.iter().any(|(k, _)| k == "packets"));
    assert!(rows.iter().any(|(k, _)| k == "sent"));
    assert!(rows.iter().any(|(k, _)| k == "usable v4"));
}

#[test]
fn metrics_service_counters() {
    let mut app = App::new().unwrap();
    assert_eq!(app.metrics.services_seen_total, 0);
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    assert_eq!(app.metrics.services_seen_total, 1);
    assert_eq!(app.metrics.services_expired_total, 0);
    // Goodbye + grace expiry removes the service.
    ingest(&mut app, &ptr_record(0));
    for svc in &mut app.services {
        svc.last_seen = Instant::now() - Duration::from_secs(300);
    }
    app.evict_expired();
    assert!(app.services.is_empty());
    assert_eq!(app.metrics.services_expired_total, 1);
}

#[test]
fn metrics_suppression_counter() {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    let ckey = ("_http._tcp.local".to_string(), 12);
    app.continuous.insert(
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
    assert_eq!(app.metrics.suppressed_continuous, 1);
    assert_eq!(app.metrics.q_sent_continuous, 0);
}

#[test]
fn metrics_offlink_row_counts_refusals() {
    let app = App::new().unwrap();
    let rows = app.metrics_rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k == "refused off-link")
        .expect("refused row");
    assert_eq!(value, "0 total");
    app.drop_stats.note("203.0.113.9:5353".parse().unwrap());
    let rows = app.metrics_rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k == "refused off-link")
        .expect("refused row");
    assert!(value.contains("1 total"), "got: {value}");
    assert!(value.contains("203.0.113.9:5353"), "got: {value}");
}

#[test]
fn interface_selection_is_stored_and_shown_in_metrics() {
    use std::collections::HashSet;
    let sel = HashSet::from(["br0".to_string()]);
    let app = App::new_with(false, Some(sel)).unwrap();
    let rows = app.metrics_rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k == "selected")
        .expect("selected row");
    assert_eq!(value, "br0");
    // No selection: no row, default behavior unchanged.
    let app = App::new().unwrap();
    assert!(app.metrics_rows().iter().all(|(k, _)| k != "selected"));
}

#[test]
fn metrics_suppression_row_shows_recency() {
    let mut app = App::new().unwrap();
    app.metrics.suppressed_continuous = 2;
    app.metrics.suppressed_times.push_back(Instant::now());
    app.metrics
        .suppressed_times
        .push_back(Instant::now() - Duration::from_secs(120));
    let rows = app.metrics_rows();
    let (_, value) = rows
        .iter()
        .find(|(k, _)| k == "suppressed queries")
        .expect("suppression row");
    assert!(value.contains("2 total"), "got: {value}");
    assert!(value.contains("1 last 60s"), "got: {value}");
}

#[test]
fn metrics_has_no_flickering_overheard_rows() {
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
    assert_eq!(app.overheard.len(), 1);
    let rows = app.metrics_rows();
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
fn metrics_overlay_suppresses_resize_hover() {
    use crossterm::event::{
        KeyCode, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent, MouseEventKind,
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
    assert_eq!(app.hover.get(), DragMode::Vertical);
    // Opening the overlay clears resize state...
    let m = KeyEvent {
        code: KeyCode::Char('m'),
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    app.handle_key(&m);
    assert!(app.show_metrics);
    assert_eq!(app.drag, DragMode::None);
    assert_eq!(app.hover.get(), DragMode::None);
    // ...and motion over a seam while open stays inert.
    app.handle_mouse(&moved);
    assert_eq!(app.hover.get(), DragMode::None);
    let down = MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column: 32,
        row: 5,
        modifiers: KeyModifiers::empty(),
    };
    app.handle_mouse(&down);
    assert_eq!(app.drag, DragMode::None);
    // Closing restores hover tracking.
    app.handle_key(&m);
    assert!(!app.show_metrics);
    app.handle_mouse(&moved);
    assert_eq!(app.hover.get(), DragMode::Vertical);
}
