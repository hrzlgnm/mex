// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

#[test]
fn self_question_hex_title_matches_remote() {
    let mut app = two_group_app();
    // Remote question with packet bytes on the selected service.
    let remote: std::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();
    let pkt = vec![0x12, 0x34, 0x01, 0x00];
    {
        let sel_idx = match app.display_items().get(app.view_state.selected_display) {
            Some(DisplayItem::Instance { index }) => *index,
            _ => panic!("expected instance selected"),
        };
        app.services[sel_idx].questions.push((
            "_ssh._tcp.local.".to_string(),
            "PTR".to_string(),
            remote,
            Instant::now(),
            pkt.clone(),
        ));
    }
    app.route_own_question("_ssh._tcp.local.", 12, false);
    // Seed fallback packet bytes distinct from any question payload:
    // the self row must surface these bytes, marked as fallback.
    let fallback = vec![0xDE, 0xAD, 0xBE, 0xEF];
    {
        let sel_idx = match app.display_items().get(app.view_state.selected_display) {
            Some(DisplayItem::Instance { index }) => *index,
            _ => panic!("expected instance selected"),
        };
        app.services[sel_idx]
            .last_event
            .as_mut()
            .expect("last event")
            .raw_bytes = fallback.clone();
    }
    let (raws, self_pos, remote_pos) = {
        let target = app.display_detail().expect("detail target");
        let raws = target.ordered_answers().len();
        let ordered = target.ordered_questions();
        let self_pos = ordered
            .iter()
            .position(|q| q.2 == SELF_SOURCE)
            .expect("self question filed");
        let remote_pos = ordered
            .iter()
            .position(|q| q.2 == remote)
            .expect("remote question filed");
        (raws, self_pos, remote_pos)
    };
    app.view_state.detail_selected = raws + self_pos;
    let (bytes, title) = app
        .selected_detail_bytes()
        .expect("self question has hex payload");
    assert_ne!(bytes, fallback);
    assert!(browse::question_fields(&bytes, "_ssh._tcp.local", "PTR").is_some());
    assert_eq!(title, " QRY PTR _ssh._tcp.local. (inferred) ");
    // Remote row returns its own query packet bytes under the
    // unmarked title.
    app.view_state.detail_selected = raws + remote_pos;
    let (rbytes, remote_title) = app
        .selected_detail_bytes()
        .expect("remote question has hex payload");
    assert_eq!(rbytes, pkt);
    assert_eq!(remote_title, " QRY PTR _ssh._tcp.local. ");
}

#[test]
fn enum_self_question_hex_title_matches_remote() {
    let mut app = App::new().unwrap();
    let enum_pos = app
        .display_items()
        .iter()
        .position(|it| matches!(it, DisplayItem::Enum { .. }))
        .expect("enum row");
    app.view_state.selected_display = enum_pos;
    app.clamp_selection();
    let remote: std::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();
    app.enum_entries[0].questions.push((
        "_services._dns-sd._udp.local.".to_string(),
        "PTR".to_string(),
        remote,
        Instant::now(),
        vec![0xAA, 0xBB],
    ));
    app.route_own_question("_services._dns-sd._udp.local.", 12, false);
    let (raws, self_pos) = {
        let target = app.display_detail().expect("enum detail target");
        let raws = target.ordered_answers().len();
        let ordered = target.ordered_questions();
        let self_pos = ordered
            .iter()
            .position(|q| q.2 == SELF_SOURCE)
            .expect("self enum question filed");
        (raws, self_pos)
    };
    app.view_state.detail_selected = raws + self_pos;
    let (bytes, title) = app
        .selected_detail_bytes()
        .expect("self enum question has hex payload");
    assert!(browse::question_fields(&bytes, "_services._dns-sd._udp.local", "PTR").is_some());
    assert_eq!(title, " QRY PTR _services._dns-sd._udp.local. (inferred) ");
}

#[test]
fn questions_table_marks_hex_source_when_hosts_focused() {
    use ratatui::style::Modifier;
    let mut app = two_group_app();
    app.route_own_question("_ssh._tcp.local.", 12, false);
    let (raws, self_pos) = {
        let target = app.display_detail().expect("detail target");
        let raws = target.ordered_answers().len();
        let pos = target
            .ordered_questions()
            .iter()
            .position(|q| q.2 == SELF_SOURCE)
            .expect("self question filed");
        (raws, pos)
    };
    app.view_state.detail_selected = raws + self_pos;
    // Hosts focus: dimmed marker, hex title names the question.
    assert_eq!(app.view_state.focus, Focus::Services);
    let marked = questions_reversed_modifiers(&app);
    assert!(
        !marked.is_empty(),
        "hex source row must stay marked without Questions focus"
    );
    assert!(
        marked.iter().all(|m| m.contains(Modifier::DIM)),
        "unfocused marker must be dim, distinct from the focused cursor"
    );
    assert!(hex_title_line(&app).contains("QRY PTR _ssh._tcp.local"));
    // Questions focus: full cursor, same title.
    app.view_state.focus = Focus::Questions;
    let marked = questions_reversed_modifiers(&app);
    assert!(!marked.is_empty());
    assert!(
        marked.iter().all(|m| !m.contains(Modifier::DIM)),
        "focused cursor must not be dimmed"
    );
    assert!(hex_title_line(&app).contains("QRY PTR _ssh._tcp.local"));
    // Hex focus: dimmed marker, same title.
    app.view_state.focus = Focus::Hex;
    let marked = questions_reversed_modifiers(&app);
    assert!(!marked.is_empty());
    assert!(marked.iter().all(|m| m.contains(Modifier::DIM)));
    assert!(hex_title_line(&app).contains("QRY PTR _ssh._tcp.local"));
    // Moving the cursor across question rows updates marker and title.
    {
        let sel_idx = match app.display_items().get(app.view_state.selected_display) {
            Some(DisplayItem::Instance { index }) => *index,
            _ => panic!("expected instance selected"),
        };
        app.services[sel_idx].questions.push((
            "shell.local".to_string(),
            "A".to_string(),
            "192.168.1.99:5353".parse().unwrap(),
            Instant::now(),
            vec![0x01, 0x02],
        ));
    }
    let target = app.display_detail().expect("detail target");
    let raws = target.ordered_answers().len();
    let remote_pos = target
        .ordered_questions()
        .iter()
        .position(|q| q.1 == "A")
        .expect("remote question filed");
    app.view_state.detail_selected = raws + remote_pos;
    let marked = questions_reversed_modifiers(&app);
    assert!(!marked.is_empty());
    assert!(hex_title_line(&app).contains("QRY A shell.local"));
}

#[test]
fn clicking_record_field_highlights_its_wire_bytes() {
    use ratatui::style::{Color, Modifier};

    let mut app = two_group_app();
    let record = app
        .services
        .iter_mut()
        .find(|service| service.instance == "Shell")
        .expect("selected service")
        .answers
        .iter_mut()
        .find(|record| record.rtype == 12)
        .expect("PTR record");
    record.wire = vec![
        0x04, b'_', b's', b's', b'h', 0x04, b'_', b't', b'c', b'p', 0x05, b'l', b'o', b'c', b'a',
        b'l', 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x17, 0x05, b'S', b'h',
        b'e', b'l', b'l', 0x04, b'_', b's', b's', b'h', 0x04, b'_', b't', b'c', b'p', 0x05, b'l',
        b'o', b'c', b'a', b'l', 0x00,
    ];
    app.services
        .iter_mut()
        .find(|service| service.instance == "Shell")
        .and_then(|service| service.answers.iter_mut().find(|record| record.rtype == 33))
        .expect("SRV record")
        .wire = srv_wire();
    app.view_state.detail_selected = 0;

    let before = render_to_buffer(&app, 160, 60);
    let selected_record = app.view_state.detail_selected;
    let (field_x, field_y) =
        find_buffer_text(&before, "Owner name").expect("owner field is displayed");
    app.mouse_down(field_x + 1, field_y);
    assert_eq!(
        app.view_state.detail_selected, selected_record,
        "clicking a field should not change the selected record"
    );

    let after = render_to_buffer(&app, 160, 60);
    let (label_x, label_y) =
        find_buffer_text(&after, "Owner name").expect("owner field remains displayed");
    assert!(
        after
            .cell((label_x, label_y))
            .is_some_and(|cell| cell.modifier.contains(Modifier::UNDERLINED)),
        "selected field label should be underlined"
    );

    let (bytes_x, bytes_y) =
        find_buffer_text(&after, "045f 7373").expect("owner bytes are displayed");
    assert!(
        after.cell((bytes_x, bytes_y)).is_some_and(|cell| {
            cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
        }),
        "owner bytes should be highlighted"
    );
    let ascii_x = bytes_x + 56;
    assert_eq!(
        after.cell((ascii_x, bytes_y)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the ASCII column should highlight the same field"
    );
    assert_eq!(
        after.cell((ascii_x + 15, bytes_y)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the final byte in the first dump row should be highlighted"
    );
    assert_eq!(
        after.cell((ascii_x, bytes_y + 1)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the owner terminator should be highlighted in the next ASCII row"
    );
    assert_ne!(
        after.cell((ascii_x + 1, bytes_y + 1)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the record type should not be highlighted in the ASCII column"
    );
    let (end_x, end_y) =
        find_buffer_text(&after, "0000 0c00").expect("owner end and record type are displayed");
    assert_eq!(
        after.cell((end_x, end_y)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the owner's terminating byte should be included"
    );
    assert_ne!(
        after.cell((end_x + 2, end_y)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the adjacent record-type byte should not be included"
    );

    app.scroll_hex_edge(false);
    let scrolled = render_to_buffer(&app, 160, 60);
    let hex_area = app.layout.hex_rect.get();
    let title_area = Rect::new(hex_area.x, hex_area.y, hex_area.width, 1);
    let (title_x, title_y) = find_buffer_text_in_rect(&scrolled, title_area, "Owner name")
        .expect("selected field remains in the pane title while scrolling");
    assert!(
        scrolled
            .cell((title_x, title_y))
            .is_some_and(|cell| cell.modifier.contains(Modifier::UNDERLINED)),
        "scrolling should not hide the selected field label"
    );

    let srv = app
        .services
        .iter_mut()
        .find(|service| service.instance == "Shell")
        .and_then(|service| service.answers.iter_mut().find(|record| record.rtype == 33))
        .expect("SRV record");
    srv.wire = srv_wire();
    app.view_state.focus = Focus::Answers;
    app.move_detail_cursor(1);
    let after_record_change = render_to_buffer(&app, 160, 60);
    let (label_x, label_y) = find_buffer_text(&after_record_change, "Owner name")
        .expect("next record field is displayed");
    assert!(
        !after_record_change
            .cell((label_x, label_y))
            .is_some_and(|cell| cell.modifier.contains(Modifier::UNDERLINED)),
        "changing records should clear the prior field selection"
    );
}

#[test]
fn clicking_question_name_highlights_the_selected_question_in_packet() {
    use ratatui::style::{Color, Modifier};

    let mut app = two_group_app();
    let mut packet = vec![0x12, 0x34, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
    append_wire_name(&mut packet, "_http._tcp.local.");
    packet.extend(12u16.to_be_bytes());
    packet.extend(1u16.to_be_bytes());
    append_wire_name(&mut packet, "Shell._ssh._tcp.local.");
    packet.extend(16u16.to_be_bytes());
    packet.extend(0x8001u16.to_be_bytes());

    select_question_row(&mut app, "Shell._ssh._tcp.local.", "TXT", packet);

    let before = render_to_buffer(&app, 160, 60);
    let (field_x, field_y) =
        find_buffer_text(&before, "QNAME").expect("question name field is displayed");
    let selected_row = app.view_state.detail_selected;
    app.mouse_down(field_x + 1, field_y);
    assert_eq!(
        app.view_state.detail_selected, selected_row,
        "clicking a question field should preserve the selected row"
    );

    let after = render_to_buffer(&app, 160, 60);
    let (class_x, class_y) =
        find_buffer_text(&after, "0001 0553 6865").expect("second question bytes are displayed");
    for x in [
        class_x + 5,
        class_x + 6,
        class_x + 7,
        class_x + 8,
        class_x + 10,
        class_x + 11,
        class_x + 12,
        class_x + 13,
    ] {
        assert!(
            after.cell((x, class_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "the selected question name bytes should be highlighted"
        );
    }
    for x in [class_x, class_x + 1, class_x + 2, class_x + 3] {
        assert_ne!(
            after.cell((x, class_y)).map(|cell| cell.fg),
            Some(Color::Yellow),
            "the preceding QCLASS bytes should not be highlighted"
        );
    }
    let (name_end_x, name_end_y) = find_buffer_text(&after, "6370 056c 6f63 616c 0000 1080 01")
        .expect("question name end and following fields are displayed");
    for x in [
        name_end_x,
        name_end_x + 1,
        name_end_x + 2,
        name_end_x + 3,
        name_end_x + 5,
        name_end_x + 6,
        name_end_x + 7,
        name_end_x + 8,
        name_end_x + 10,
        name_end_x + 11,
        name_end_x + 12,
        name_end_x + 13,
        name_end_x + 15,
        name_end_x + 16,
        name_end_x + 17,
        name_end_x + 18,
        name_end_x + 20,
        name_end_x + 21,
    ] {
        assert!(
            after.cell((x, name_end_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "all encoded QNAME bytes through its root terminator should be highlighted"
        );
    }
    for x in [
        name_end_x + 22,
        name_end_x + 23,
        name_end_x + 25,
        name_end_x + 26,
    ] {
        assert_ne!(
            after.cell((x, name_end_y)).map(|cell| cell.fg),
            Some(Color::Yellow),
            "QTYPE bytes after QNAME should not be highlighted"
        );
    }

    let (field_x, field_y) =
        find_buffer_text(&after, "QTYPE").expect("question type field is displayed");
    app.mouse_down(field_x + 1, field_y);
    let type_selected = render_to_buffer(&app, 160, 60);
    let (type_x, type_y) = find_buffer_text(&type_selected, "616c 0000 1080 01")
        .expect("question type bytes are displayed");
    for x in [type_x + 7, type_x + 8, type_x + 10, type_x + 11] {
        assert!(
            type_selected.cell((x, type_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "QTYPE bytes should be highlighted"
        );
    }
    for x in [
        type_x + 5,
        type_x + 6,
        type_x + 12,
        type_x + 13,
        type_x + 15,
        type_x + 16,
    ] {
        assert_ne!(
            type_selected.cell((x, type_y)).map(|cell| cell.fg),
            Some(Color::Yellow),
            "QNAME and QCLASS bytes should not be highlighted for QTYPE"
        );
    }

    let (field_x, field_y) = find_buffer_text(&type_selected, "QCLASS / QU")
        .expect("question class and QU field is displayed");
    app.mouse_down(field_x + 1, field_y);
    let class_selected = render_to_buffer(&app, 160, 60);
    for x in [type_x + 12, type_x + 13, type_x + 15, type_x + 16] {
        assert!(
            class_selected.cell((x, type_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "QCLASS and QU bytes should be highlighted"
        );
    }
    for x in [type_x + 7, type_x + 8, type_x + 10, type_x + 11] {
        assert_ne!(
            class_selected.cell((x, type_y)).map(|cell| cell.fg),
            Some(Color::Yellow),
            "QTYPE bytes should not be highlighted for QCLASS / QU"
        );
    }

    app.scroll_hex_edge(false);
    let scrolled = render_to_buffer(&app, 160, 60);
    let hex_area = app.layout.hex_rect.get();
    let title_area = Rect::new(hex_area.x, hex_area.y, hex_area.width, 1);
    let (title_x, title_y) = find_buffer_text_in_rect(&scrolled, title_area, "QCLASS / QU")
        .expect("selected question field stays visible while scrolling");
    assert!(
        scrolled
            .cell((title_x, title_y))
            .is_some_and(|cell| cell.modifier.contains(Modifier::UNDERLINED)),
        "scrolling should not hide the selected question field label"
    );
}

#[test]
fn clicking_compressed_question_name_highlights_its_pointer_bytes() {
    use ratatui::style::{Color, Modifier};

    let mut app = two_group_app();
    let mut packet = vec![0x12, 0x34, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
    append_wire_name(&mut packet, "Shell._ssh._tcp.local.");
    packet.extend(12u16.to_be_bytes());
    packet.extend(1u16.to_be_bytes());
    packet.extend([0xc0, 0x0c]);
    packet.extend(16u16.to_be_bytes());
    packet.extend(0x8001u16.to_be_bytes());

    select_question_row(&mut app, "Shell._ssh._tcp.local.", "TXT", packet);

    let before = render_to_buffer(&app, 160, 60);
    let (field_x, field_y) =
        find_buffer_text(&before, "QNAME").expect("question name field is displayed");
    app.mouse_down(field_x + 1, field_y);

    let after = render_to_buffer(&app, 160, 60);
    let (pointer_x, pointer_y) = find_buffer_text(&after, "01c0 0c00 1080 01")
        .expect("compressed question and following fields are displayed");
    for x in [pointer_x + 2, pointer_x + 3, pointer_x + 5, pointer_x + 6] {
        assert!(
            after.cell((x, pointer_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "the encoded compression pointer should be highlighted"
        );
    }
    for x in [
        pointer_x,
        pointer_x + 1,
        pointer_x + 7,
        pointer_x + 8,
        pointer_x + 10,
        pointer_x + 11,
        pointer_x + 12,
        pointer_x + 13,
        pointer_x + 15,
        pointer_x + 16,
    ] {
        assert_ne!(
            after.cell((x, pointer_y)).map(|cell| cell.fg),
            Some(Color::Yellow),
            "the preceding QCLASS and following QTYPE/QCLASS bytes should stay unhighlighted"
        );
    }
}

#[test]
fn ambiguous_question_mapping_stays_byte_only() {
    let mut app = two_group_app();
    let mut packet = vec![0x12, 0x34, 0, 0, 0, 2, 0, 0, 0, 0, 0, 0];
    for _ in 0..2 {
        append_wire_name(&mut packet, "Shell._ssh._tcp.local.");
        packet.extend(12u16.to_be_bytes());
        packet.extend(1u16.to_be_bytes());
    }

    select_question_row(&mut app, "Shell._ssh._tcp.local.", "PTR", packet);

    let buffer = render_to_buffer(&app, 160, 60);
    assert!(
        find_buffer_text(&buffer, "QNAME").is_none(),
        "duplicate matching questions should not guess which wire occurrence is selected"
    );
}

#[test]
fn malformed_question_packet_stays_byte_only() {
    let mut app = two_group_app();
    let packet = vec![0x12, 0x34, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 5, b'S', b'h'];
    select_question_row(&mut app, "Shell._ssh._tcp.local.", "PTR", packet);

    let buffer = render_to_buffer(&app, 160, 60);
    assert!(
        find_buffer_text(&buffer, "QNAME").is_none(),
        "malformed question bytes should not receive guessed field ranges"
    );
}

#[test]
fn clicking_own_question_field_highlights_its_query_bytes() {
    use ratatui::style::{Color, Modifier};

    let mut app = two_group_app();
    let fallback = vec![0xde, 0xad, 0xbe, 0xef];
    let selected_service = match app.display_items().get(app.view_state.selected_display) {
        Some(DisplayItem::Instance { index }) => *index,
        _ => panic!("expected instance selected"),
    };
    app.services[selected_service]
        .last_event
        .as_mut()
        .expect("latest event")
        .raw_bytes = fallback;
    app.route_own_question("Shell._ssh._tcp.local.", 12, false);
    let raw_count = app
        .display_detail()
        .expect("selected service")
        .ordered_answers()
        .len();
    app.view_state.detail_selected = raw_count;
    app.view_state.focus = Focus::Questions;

    let before = render_to_buffer(&app, 160, 60);
    assert!(
        find_buffer_text(&before, "(inferred)").is_some(),
        "own question bytes should be identified as inferred"
    );
    let (field_x, field_y) =
        find_buffer_text(&before, "QNAME").expect("own question name field is displayed");
    let selected_row = app.view_state.detail_selected;
    app.mouse_down(field_x + 1, field_y);
    assert_eq!(
        app.view_state.detail_selected, selected_row,
        "clicking an own question field should preserve its selected row"
    );

    let after = render_to_buffer(&app, 160, 60);
    let (label_x, label_y) =
        find_buffer_text(&after, "QNAME").expect("own question field remains displayed");
    assert!(
        after
            .cell((label_x, label_y))
            .is_some_and(|cell| cell.modifier.contains(Modifier::UNDERLINED)),
        "clicking the own question field should mark its label"
    );
    let (name_x, name_y) = find_buffer_text(&after, "0553 6865")
        .expect("generated packet's QNAME bytes should be displayed");
    for x in [
        name_x,
        name_x + 1,
        name_x + 2,
        name_x + 3,
        name_x + 5,
        name_x + 6,
        name_x + 7,
        name_x + 8,
    ] {
        assert!(
            after.cell((x, name_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "clicking an own question should highlight the generated query's QNAME"
        );
    }
    assert!(
        find_buffer_text(&after, "dead beef").is_none(),
        "unrelated fallback bytes must not replace the own question packet"
    );
}

#[test]
fn clicking_srv_port_highlights_only_the_port_bytes() {
    use ratatui::style::{Color, Modifier};

    let mut app = two_group_app();
    let service = app
        .services
        .iter_mut()
        .find(|service| service.instance == "Shell")
        .expect("selected service");
    let record = service
        .answers
        .iter_mut()
        .find(|record| record.rtype == 33)
        .expect("SRV record");
    record.wire = srv_wire();
    app.view_state.detail_selected = app
        .display_detail()
        .and_then(|detail| {
            detail
                .ordered_answers()
                .iter()
                .position(|record| record.rtype == 33)
        })
        .expect("SRV record position");

    let before = render_to_buffer(&app, 100, 60);
    let (field_x, field_y) =
        find_buffer_text(&before, "Port").expect("SRV port field is displayed");
    app.mouse_down(field_x + 1, field_y);

    let after = render_to_buffer(&app, 100, 60);
    let (bytes_x, bytes_y) =
        find_buffer_text(&after, "0023 8c05").expect("SRV port bytes are displayed");
    for x in [bytes_x + 2, bytes_x + 3, bytes_x + 5, bytes_x + 6] {
        assert!(
            after.cell((x, bytes_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "each port hex digit should be highlighted"
        );
    }
    assert_ne!(
        after.cell((bytes_x, bytes_y)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the preceding SRV byte should not be highlighted"
    );
    assert_ne!(
        after.cell((bytes_x + 7, bytes_y)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the following target-name byte should not be highlighted"
    );
}

#[test]
fn clicking_ipv4_address_highlights_its_four_bytes() {
    use ratatui::style::{Color, Modifier};

    let mut app = two_group_app();
    let mut wire = Vec::new();
    append_wire_name(&mut wire, "host.local.");
    wire.extend(1u16.to_be_bytes());
    wire.extend(0x8001u16.to_be_bytes());
    wire.extend(120u32.to_be_bytes());
    wire.extend(4u16.to_be_bytes());
    wire.extend([192, 0, 2, 1]);
    let mut record = raw_record("host.local.", 1, "A", "192.0.2.1", 120);
    record.wire = wire;
    app.services
        .iter_mut()
        .find(|service| service.instance == "Shell")
        .expect("selected service")
        .answers
        .push(record);
    app.view_state.detail_selected = app
        .display_detail()
        .and_then(|detail| {
            detail
                .ordered_answers()
                .iter()
                .position(|record| record.rtype == 1)
        })
        .expect("A record position");

    let before = render_to_buffer(&app, 100, 60);
    let (field_x, field_y) =
        find_buffer_text(&before, "IPv4 address").expect("address field is displayed");
    app.mouse_down(field_x + 1, field_y);

    let after = render_to_buffer(&app, 100, 60);
    let (bytes_x, bytes_y) =
        find_buffer_text(&after, "c000 0201").expect("IPv4 address bytes are displayed");
    for x in [
        bytes_x,
        bytes_x + 1,
        bytes_x + 2,
        bytes_x + 3,
        bytes_x + 5,
        bytes_x + 6,
        bytes_x + 7,
        bytes_x + 8,
    ] {
        assert!(
            after.cell((x, bytes_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "each IPv4 address hex digit should be highlighted"
        );
    }
}

#[test]
fn unknown_record_data_stays_opaque() {
    let mut app = two_group_app();
    let mut wire = Vec::new();
    append_wire_name(&mut wire, "host.local.");
    wire.extend(99u16.to_be_bytes());
    wire.extend(1u16.to_be_bytes());
    wire.extend(120u32.to_be_bytes());
    wire.extend(4u16.to_be_bytes());
    wire.extend([1, 2, 3, 4]);
    let mut record = raw_record("host.local.", 99, "TYPE99", "01020304", 120);
    record.wire = wire;
    app.services
        .iter_mut()
        .find(|service| service.instance == "Shell")
        .expect("selected service")
        .answers
        .push(record);
    app.view_state.detail_selected = app
        .display_detail()
        .and_then(|detail| {
            detail
                .ordered_answers()
                .iter()
                .position(|record| record.rtype == 99)
        })
        .expect("unknown record position");

    let buffer = render_to_buffer(&app, 160, 60);
    let hex_area = app.layout.hex_rect.get();
    assert!(
        find_buffer_text_in_rect(&buffer, hex_area, "RDATA").is_some(),
        "unknown record data should remain identifiable as RDATA"
    );
    assert!(
        find_buffer_text_in_rect(&buffer, hex_area, "IPv4 address").is_none(),
        "unknown record data should not be given invented subfields"
    );
    assert!(
        find_buffer_text_in_rect(&buffer, hex_area, "PTR target").is_none(),
        "unknown record data should not be interpreted as a known name field"
    );
}

#[test]
fn clicking_txt_string_highlights_its_length_and_data() {
    use ratatui::style::{Color, Modifier};

    let mut app = two_group_app();
    let mut record = raw_record("Shell._ssh._tcp.local.", 16, "TXT", "a=1; b=2", 120);
    let mut wire = Vec::new();
    append_wire_name(&mut wire, "Shell._ssh._tcp.local.");
    wire.extend(16u16.to_be_bytes());
    wire.extend(0x8001u16.to_be_bytes());
    wire.extend(120u32.to_be_bytes());
    wire.extend(8u16.to_be_bytes());
    wire.extend([3, b'a', b'=', b'1', 3, b'b', b'=', b'2']);
    record.wire = wire;
    ingest(&mut app, &record);
    app.view_state.detail_selected = app
        .display_detail()
        .and_then(|detail| {
            detail
                .ordered_answers()
                .iter()
                .position(|record| record.rtype == 16)
        })
        .expect("TXT record position");

    let before = render_to_buffer(&app, 100, 60);
    let (field_x, field_y) =
        find_buffer_text(&before, "TXT string 2").expect("second TXT string is displayed");
    app.mouse_down(field_x + 1, field_y);

    let after = render_to_buffer(&app, 100, 60);
    let (bytes_x, bytes_y) =
        find_buffer_text(&after, "3103 623d").expect("second TXT string bytes are displayed");
    for x in [
        bytes_x + 2,
        bytes_x + 3,
        bytes_x + 5,
        bytes_x + 6,
        bytes_x + 7,
    ] {
        assert!(
            after.cell((x, bytes_y)).is_some_and(|cell| {
                cell.fg == Color::Yellow && cell.modifier.contains(Modifier::UNDERLINED)
            }),
            "each byte of the second TXT string should be highlighted"
        );
    }
    assert_ne!(
        after.cell((bytes_x, bytes_y)).map(|cell| cell.fg),
        Some(Color::Yellow),
        "the first TXT string should not be highlighted"
    );
}

#[test]
fn hex_pane_shows_focus_cue() {
    use ratatui::style::Modifier;
    // Dump state: bold body iff focused.
    let mut app = two_group_app();
    app.view_state.focus = Focus::Hex;
    let (mods, _) = hex_body_marks(&app, 100, 30);
    assert!(!mods.is_empty());
    assert!(
        mods.iter().any(|m| m.contains(Modifier::BOLD)),
        "focused hex body must be bold"
    );
    app.view_state.focus = Focus::Services;
    let (mods, _) = hex_body_marks(&app, 100, 30);
    assert!(!mods.is_empty());
    assert!(
        mods.iter().all(|m| !m.contains(Modifier::BOLD)),
        "unfocused hex body must not be bold"
    );
    // Empty state: cue present, same rule.
    let mut empty_app = App::new().unwrap();
    empty_app.view_state.focus = Focus::Hex;
    let (mods, _) = hex_body_marks(&empty_app, 100, 30);
    assert!(mods.iter().any(|m| m.contains(Modifier::BOLD)));
    empty_app.view_state.focus = Focus::Services;
    let (mods, _) = hex_body_marks(&empty_app, 100, 30);
    assert!(mods.iter().all(|m| !m.contains(Modifier::BOLD)));
    // Scrolled state: tall dump, small pane, offset forced.
    let mut app = two_group_app();
    {
        let sel_idx = match app.display_items().get(app.view_state.selected_display) {
            Some(DisplayItem::Instance { index }) => *index,
            _ => panic!("expected instance selected"),
        };
        app.services[sel_idx]
            .last_event
            .as_mut()
            .expect("last event")
            .raw_bytes = vec![0xAB; 256];
    }
    app.layout.hex_offset.set(5);
    app.view_state.focus = Focus::Hex;
    // Tall enough that the scrolled dump keeps a viewport in the
    // four-pane stack.
    let (mods, title) = hex_body_marks(&app, 100, 20);
    assert!(title.contains('↕'), "dump must be scrolled, got: {title}");
    assert!(mods.iter().any(|m| m.contains(Modifier::BOLD)));
    app.view_state.focus = Focus::Services;
    let (mods, _) = hex_body_marks(&app, 100, 20);
    assert!(mods.iter().all(|m| !m.contains(Modifier::BOLD)));
}

#[test]
fn answers_table_marks_hex_source_when_hosts_focused() {
    use ratatui::style::Modifier;
    let mut app = two_group_app();
    // Services focus is the Hosts pane.
    assert_eq!(app.view_state.focus, Focus::Services);
    // The detail cursor sits on a record, so the hex pane follows it.
    assert!(app.selected_detail_entry().is_some());
    let marked = answers_reversed_modifiers(&app);
    assert!(
        !marked.is_empty(),
        "hex source row must stay marked without Answers focus"
    );
    assert!(
        marked.iter().all(|m| m.contains(Modifier::DIM)),
        "unfocused marker must be dim, distinct from the focused cursor"
    );
    // Focused behavior is unchanged: full cursor, no dimming.
    app.view_state.focus = Focus::Answers;
    let marked = answers_reversed_modifiers(&app);
    assert!(!marked.is_empty());
    assert!(
        marked.iter().all(|m| !m.contains(Modifier::DIM)),
        "focused cursor must not be dimmed"
    );
    // Moving the host selection keeps marker and hex dump in sync: the
    // marker follows the detail cursor (test answers carry no wire
    // bytes, so the dump itself is covered by the title tests).
    app.view_state.focus = Focus::Services;
    select_instance(&mut app, "Test");
    assert!(app.selected_detail_entry().is_some());
    let marked = answers_reversed_modifiers(&app);
    assert!(!marked.is_empty(), "marker must follow the host selection");
}

#[test]
fn hex_pane_scrolls_and_resets() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    use ratatui::layout::Rect;
    let mut app = App::new().unwrap();
    service_with_txt(&mut app, "a=1; b=2");
    let plain = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    // Tab reaches Hex right after Questions; the focused pane lights
    // its border.
    app.handle_key(&plain(KeyCode::Tab));
    app.handle_key(&plain(KeyCode::Tab));
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Hex);
    // Viewport is recorded at draw; fake 10 rows for the scroll math.
    app.layout.hex_viewport.set(10);
    app.handle_key(&plain(KeyCode::Char('j')));
    assert_eq!(app.layout.hex_offset.get(), 1);
    app.handle_key(&plain(KeyCode::Char(' ')));
    assert_eq!(app.layout.hex_offset.get(), 11);
    // And back: a line with `k`, a page with PageUp.
    app.handle_key(&plain(KeyCode::Char('k')));
    assert_eq!(app.layout.hex_offset.get(), 10);
    app.handle_key(&plain(KeyCode::PageUp));
    assert_eq!(app.layout.hex_offset.get(), 0);
    app.handle_key(&plain(KeyCode::Down));
    assert_eq!(app.layout.hex_offset.get(), 1);
    app.handle_key(&plain(KeyCode::Home));
    assert_eq!(app.layout.hex_offset.get(), 0);
    app.handle_key(&plain(KeyCode::End));
    assert!(app.layout.hex_offset.get() > 1000);
    // Moving the record cursor restarts the dump at the top.
    app.handle_key(&plain(KeyCode::BackTab));
    app.handle_key(&plain(KeyCode::BackTab));
    assert_eq!(app.view_state.focus, Focus::Answers);
    app.handle_key(&plain(KeyCode::Char('k')));
    assert_eq!(app.layout.hex_offset.get(), 0);
    // Clicking another row restarts the dump; re-clicking keeps scroll.
    app.layout.answers_rect.set(Rect::new(33, 3, 67, 30));
    app.layout.right_rect.set(Rect::new(33, 3, 67, 30));
    app.layout.detail_offset.set(0);
    app.layout.hex_offset.set(5);
    app.click_answers(3 + 2 + 1);
    assert_eq!(app.view_state.detail_selected, 0);
    assert_eq!(app.layout.hex_offset.get(), 0);
    app.layout.hex_offset.set(5);
    app.click_answers(3 + 2 + 1);
    assert_eq!(app.layout.hex_offset.get(), 5);
    // Clicking the hex pane focuses it for scrolling.
    app.layout.left_rect.set(Rect::new(0, 3, 33, 30));
    app.layout.answers_rect.set(Rect::new(33, 3, 67, 8));
    app.layout.questions_rect.set(Rect::new(33, 11, 67, 13));
    app.layout.hex_rect.set(Rect::new(33, 24, 67, 9));
    app.view_state.focus = Focus::Services;
    app.mouse_down(40, 25);
    assert_eq!(app.view_state.focus, Focus::Hex);
}

#[test]
fn hex_offset_resets_on_target_change() {
    let mut app = two_group_app();
    app.layout.hex_offset.set(7);
    select_instance(&mut app, "Test");
    assert_eq!(app.layout.hex_offset.get(), 0);
}

#[test]
fn snap_to_focused_table_resets_hex_scroll() {
    use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
    let mut app = two_group_app();
    let plain = |code| KeyEvent {
        code,
        modifiers: KeyModifiers::empty(),
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    };
    // One question so Tab into Questions snaps the cursor off its record.
    let src: std::net::SocketAddr = "192.168.1.9:5353".parse().unwrap();
    let raw_count = {
        let sel_idx = match app.display_items().get(app.view_state.selected_display) {
            Some(DisplayItem::Instance { index }) => *index,
            _ => panic!("expected instance selected"),
        };
        app.services[sel_idx].questions.push((
            "_http._tcp.local".to_string(),
            "PTR".to_string(),
            src,
            Instant::now(),
            Vec::new(),
        ));
        app.services[sel_idx].ordered_answers().len()
    };
    // Park the cursor on a record, scroll the hex dump, then Tab across:
    // the snap moves the cursor and must restart the dump at the top.
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Answers);
    assert!(app.view_state.detail_selected < raw_count);
    app.layout.hex_offset.set(9);
    app.handle_key(&plain(KeyCode::Tab));
    assert_eq!(app.view_state.focus, Focus::Questions);
    assert_eq!(app.view_state.detail_selected, raw_count);
    assert_eq!(app.layout.hex_offset.get(), 0);
}

/// REVERSED-carrying cell styles inside the Questions pane body
/// (border and header rows excluded). No other style in that pane uses
/// REVERSED, so any hit is the cursor marker.
fn questions_reversed_modifiers(app: &App) -> Vec<ratatui::style::Modifier> {
    // Rects are recorded during draw, so render first.
    let buf = render_to_buffer(app, 100, 30);
    let area = app.layout.questions_rect.get();
    let mut out = Vec::new();
    for y in (area.y + 2)..(area.y + area.height.saturating_sub(1)) {
        for x in (area.x + 1)..(area.x + area.width.saturating_sub(1)) {
            if let Some(cell) = buf.cell((x, y)) {
                if cell.modifier.contains(ratatui::style::Modifier::REVERSED) {
                    out.push(cell.modifier);
                }
            }
        }
    }
    out
}

/// Top border line text of the hex pane (carries the pane title).
fn hex_title_line(app: &App) -> String {
    let buf = render_to_buffer(app, 100, 30);
    let area = app.layout.hex_rect.get();
    let mut s = String::new();
    for x in area.x..(area.x + area.width) {
        if let Some(cell) = buf.cell((x, area.y)) {
            s.push_str(cell.symbol());
        }
    }
    s
}

/// Hex pane body cell modifiers (excluding the two dump header lines)
/// plus the hex pane title line, rendered at the given terminal size.
fn hex_body_marks(app: &App, width: u16, height: u16) -> (Vec<ratatui::style::Modifier>, String) {
    let buf = render_to_buffer(app, width, height);
    let area = app.layout.hex_rect.get();
    let empty = app.selected_detail_bytes().is_none() && app.latest_event_for_selected().is_none();
    let offset = app.layout.hex_offset.get();
    let mut mods = Vec::new();
    for (i, y) in ((area.y + 1)..(area.y + area.height.saturating_sub(1))).enumerate() {
        // Skip the "Hex dump" header + blank line; the empty message
        // has no header lines.
        if !empty && offset + i < 2 {
            continue;
        }
        for x in (area.x + 1)..(area.x + area.width.saturating_sub(1)) {
            if let Some(cell) = buf.cell((x, y)) {
                mods.push(cell.modifier);
            }
        }
    }
    let mut title = String::new();
    for x in area.x..(area.x + area.width) {
        if let Some(cell) = buf.cell((x, area.y)) {
            title.push_str(cell.symbol());
        }
    }
    (mods, title)
}

fn find_buffer_text(buffer: &ratatui::buffer::Buffer, needle: &str) -> Option<(u16, u16)> {
    find_buffer_text_in_rect(buffer, buffer.area, needle)
}

fn find_buffer_text_in_rect(
    buffer: &ratatui::buffer::Buffer,
    area: Rect,
    needle: &str,
) -> Option<(u16, u16)> {
    for y in area.y..area.y.saturating_add(area.height) {
        let line: String = (area.x..area.x.saturating_add(area.width))
            .filter_map(|x| buffer.cell((x, y)).map(|cell| cell.symbol()))
            .collect();
        if let Some(byte_index) = line.find(needle) {
            let cell_offset = line[..byte_index].chars().count();
            return Some((area.x.saturating_add(cell_offset as u16), y));
        }
    }
    None
}

fn append_wire_name(wire: &mut Vec<u8>, name: &str) {
    for label in name.trim_end_matches('.').split('.') {
        wire.push(label.len() as u8);
        wire.extend_from_slice(label.as_bytes());
    }
    wire.push(0);
}

fn srv_wire() -> Vec<u8> {
    let mut wire = Vec::new();
    append_wire_name(&mut wire, "Shell._ssh._tcp.local.");
    wire.extend(33u16.to_be_bytes());
    wire.extend(0x8001u16.to_be_bytes());
    wire.extend(120u32.to_be_bytes());
    let mut rdata = vec![0, 0, 0, 0, 0x23, 0x8c];
    append_wire_name(&mut rdata, "shell.local.");
    wire.extend((rdata.len() as u16).to_be_bytes());
    wire.extend(rdata);
    wire
}

/// REVERSED-carrying cell styles inside the Answers pane body (border
/// and header rows excluded). Backs the unfocused-marker regression
/// test; no other style in that pane uses REVERSED, so any hit is the
/// cursor marker.
fn answers_reversed_modifiers(app: &App) -> Vec<ratatui::style::Modifier> {
    let buf = render_to_buffer(app, 100, 30);
    let area = app.layout.answers_rect.get();
    let mut out = Vec::new();
    for y in (area.y + 2)..(area.y + area.height.saturating_sub(1)) {
        for x in (area.x + 1)..(area.x + area.width.saturating_sub(1)) {
            if let Some(cell) = buf.cell((x, y)) {
                if cell.modifier.contains(ratatui::style::Modifier::REVERSED) {
                    out.push(cell.modifier);
                }
            }
        }
    }
    out
}

fn select_question_row(app: &mut App, name: &str, rtype: &str, packet: Vec<u8>) {
    let raw_count = app
        .display_detail()
        .expect("selected service")
        .ordered_answers()
        .len();
    let selected_service = match app.display_items().get(app.view_state.selected_display) {
        Some(DisplayItem::Instance { index }) => *index,
        _ => panic!("expected instance selected"),
    };
    app.services[selected_service].questions.push((
        name.to_string(),
        rtype.to_string(),
        "192.168.1.99:5353".parse().unwrap(),
        Instant::now(),
        packet,
    ));
    app.view_state.detail_selected = raw_count;
    app.view_state.focus = Focus::Questions;
}
