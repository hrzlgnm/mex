// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;
use std::net::SocketAddr;

mod answer_sections;
mod conflicting_answers;
mod denials;
mod devices;
mod diagnostics;
mod finding_owners;
mod finding_targets;
mod finding_wrap;
mod hex;
mod ingest;
mod input;
mod manual_refresh;
mod out_of_scope;
mod per_link_copies;
mod per_nic_answers;
mod question_window;
mod questions;
mod run_loop;
mod rusage;
mod schedule;
mod scheduler;
mod service_identity;
mod srv_target;
mod state_dump;
mod transmit_state;
mod view;

fn test_source() -> SocketAddr {
    "192.168.1.2:5353".parse().unwrap()
}

/// Wire labels of a name as the parser keys it (presentation form):
/// `\.` stays inside its label, as in `Á\.a._test._tcp.local.`.
fn wire_labels(name: &str) -> Vec<Vec<u8>> {
    browse::presentation_labels(name)
        .into_iter()
        .map(String::into_bytes)
        .collect()
}

fn raw_record(name: &str, rtype: u16, rtype_str: &str, rdata: &str, ttl: u32) -> browse::RawRecord {
    browse::RawRecord {
        name: name.to_string(),
        owner_labels: wire_labels(name),
        ptr_target_labels: (rtype == 12).then(|| wire_labels(rdata)),
        rtype,
        rtype_str: rtype_str.to_string(),
        flush_bit: false,
        qu: false,
        invalid_utf8: false,
        ttl,
        rdata: rdata.to_string(),
        wire: Vec::new(),
        source: test_source(),
        iface: String::new(),
        ifindex: 0,
        dst_is_multicast: true,
        section: browse::RecordSection::Answer,
        received_at: Instant::now(),
        trigger: None,
    }
}

fn ptr_record(ttl: u32) -> browse::RawRecord {
    raw_record(
        "_http._tcp.local.",
        12,
        "PTR",
        "Test._http._tcp.local.",
        ttl,
    )
}

fn srv_record(ttl: u32) -> browse::RawRecord {
    let mut r = raw_record(
        "Test._http._tcp.local.",
        33,
        "SRV",
        "0 0 80 test.local.",
        ttl,
    );
    // Unique records SHOULD set the bit; the helper models the
    // well-behaved case so pane tests only see their intended finding.
    r.flush_bit = true;
    r
}

fn event_for(rec: &browse::RawRecord) -> browse::Event {
    browse::Event {
        answers: vec![rec.clone()],
        questions: Vec::new(),
        query_kas: Vec::new(),
        rcode: Some(0),
        received_at: Instant::now(),
        raw_bytes: Vec::new(),
        source: test_source(),
    }
}

/// Backdate the refresh schedule of every tracked row of a question
/// so the next `requery_expiring` pass treats its attempt as due.
fn make_refresh_due(app: &mut App, name: &str, rtype: u16) {
    for (row, state) in app.scheduler.refresh_rows_mut().iter_mut() {
        if row.0 == name && row.1 == rtype {
            state.next_due = Instant::now() - Duration::from_millis(1);
        }
    }
}

fn ingest(app: &mut App, rec: &browse::RawRecord) {
    let ev = event_for(rec);
    app.ingest_event(&ev);
}

fn ingest_packet(app: &mut App, event: browse::Event) {
    let (tx, rx) = mpsc::channel();
    app.rx = rx;
    tx.send(event).unwrap();
    app.drain_events();
}

fn mark_address_queries(app: &mut App, hostname: &str, age: Duration) {
    let sent_at = Instant::now() - age;
    for rtype in [1, 28] {
        app.scheduler.query_history_mut().insert(
            Scheduler::provenance_key(hostname, rtype),
            InterestQueryState {
                transmitted: Some(sent_at),
                ..InterestQueryState::default()
            },
        );
    }
}

fn txt_record(rdata: &str) -> browse::RawRecord {
    raw_record("Test._http._tcp.local.", 16, "TXT", rdata, 120)
}

fn service_with_txt(app: &mut App, rdata: &str) {
    ingest(app, &ptr_record(120));
    ingest(app, &txt_record(rdata));
    ingest(app, &srv_record(120));
    // Settle the cursors onto the instance row like the main loop does,
    // then park the Tab cursor on the TXT row (it defaults to the
    // first record, usually PTR).
    app.evict_expired();
    select_instance(app, "Test");
    assert!(app.selected_service().is_some());
    let idx = {
        let svc = app.display_service().expect("service displayed");
        svc.ordered_answers()
            .iter()
            .position(|r| r.rtype == 16)
            .expect("TXT record merged into service")
    };
    // Park the Tab cursor on the TXT row without going through
    // sync_detail_cursor (which would re-anchor to the old PTR row).
    app.view_state.detail_selected = idx;
    app.detail_anchor = app
        .display_detail()
        .and_then(|d| App::identity_at_detail(&d, idx));
}

/// Left-button mouse event builders shared by the resize tests:
/// down starts a drag, drag follows the pointer, up releases.
fn mouse_down(column: u16, row: u16) -> crossterm::event::MouseEvent {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    MouseEvent {
        kind: MouseEventKind::Down(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    }
}

/// Drag with the left button held (see `mouse_down`).
fn mouse_drag(column: u16, row: u16) -> crossterm::event::MouseEvent {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    MouseEvent {
        kind: MouseEventKind::Drag(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    }
}

/// Release with the pointer at this position (see `mouse_down`).
fn mouse_up(column: u16, row: u16) -> crossterm::event::MouseEvent {
    use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
    MouseEvent {
        kind: MouseEventKind::Up(MouseButton::Left),
        column,
        row,
        modifiers: KeyModifiers::empty(),
    }
}

/// Grab cell of each seam kind under the current layout: the cell a
/// `mouse_down` there starts the matching drag from.
fn seam_grab_cell(app: &App, mode: DragMode) -> (u16, u16) {
    let left = app.layout.left_rect.get();
    let answers = app.layout.answers_rect.get();
    match mode {
        DragMode::Vertical => (left.x + left.width - 1, left.y + 5),
        DragMode::HorizUpper => (answers.x + 5, app.layout.questions_rect.get().y),
        DragMode::HorizLower => (answers.x + 5, app.layout.hex_rect.get().y),
        DragMode::None => unreachable!("None has no seam to grab"),
    }
}

/// Render the full UI into a test buffer at the given size. Shared
/// core for the render-based regression tests below.
fn render_to_buffer(app: &App, width: u16, height: u16) -> ratatui::buffer::Buffer {
    use ratatui::backend::TestBackend;
    let mut terminal = ratatui::Terminal::new(TestBackend::new(width, height)).unwrap();
    terminal.draw(|f| crate::ui::draw(f, app)).unwrap();
    terminal.backend().buffer().clone()
}

/// Two hosts (shell.local, test.local) with one instance each, cursor
/// settled on the first service row (past the enumeration group).
fn two_group_app() -> App {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    ingest(
        &mut app,
        &raw_record("_ssh._tcp.local.", 12, "PTR", "Shell._ssh._tcp.local.", 120),
    );
    ingest(
        &mut app,
        &raw_record(
            "Shell._ssh._tcp.local.",
            33,
            "SRV",
            "0 0 22 shell.local.",
            120,
        ),
    );
    app.evict_expired();
    select_instance(&mut app, "Shell");
    app
}

/// Move the cursor onto the instance row with this name.
fn select_instance(app: &mut App, instance: &str) {
    let items = app.display_items();
    for (i, it) in items.iter().enumerate() {
        if let DisplayItem::Instance { index } = it {
            if app.services[*index].instance == instance {
                app.view_state.selected_display = i;
                break;
            }
        }
    }
    app.clamp_selection();
}

/// Enumeration rows from two responders share one refresh key: a
/// short-TTL row that keeps being answered, and a long-TTL row whose
/// responder went silent, sitting inside its 80-100% window.
fn app_with_stale_enum_row() -> App {
    let mut app = App::new().unwrap();
    let mut fresh = raw_record(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_http._tcp.local.",
        60,
    );
    fresh.source = "192.168.1.3:5353".parse().unwrap();
    let mut stale = raw_record(
        "_services._dns-sd._udp.local.",
        12,
        "PTR",
        "_ipp._tcp.local.",
        4500,
    );
    stale.source = "192.168.1.4:5353".parse().unwrap();
    stale.received_at = Instant::now() - Duration::from_secs(3825); // 85%
    app.enum_entries[0].answers.push(fresh);
    app.enum_entries[0].answers.push(stale);
    app
}

fn enum_row(target: &str, ttl: u32, source: &str, age_secs: u64) -> browse::RawRecord {
    let mut rec = raw_record("_services._dns-sd._udp.local.", 12, "PTR", target, ttl);
    rec.source = source.parse().unwrap();
    rec.received_at = Instant::now() - Duration::from_secs(age_secs);
    rec
}

fn query_event(
    name: &str,
    rtype: u16,
    rtype_str: &str,
    qu: bool,
    kas: Vec<browse::RawRecord>,
    source: std::net::SocketAddr,
) -> browse::Event {
    let q = browse::RawRecord {
        name: name.to_string(),
        owner_labels: wire_labels(name),
        ptr_target_labels: None,
        rtype,
        rtype_str: rtype_str.to_string(),
        flush_bit: false,
        qu,
        invalid_utf8: false,
        ttl: 0,
        rdata: String::new(),
        wire: Vec::new(),
        source,
        iface: String::new(),
        ifindex: 0,
        dst_is_multicast: true,
        section: browse::RecordSection::Question,
        received_at: Instant::now(),
        trigger: None,
    };
    browse::Event {
        answers: Vec::new(),
        questions: vec![q],
        query_kas: kas,
        rcode: None,
        received_at: Instant::now(),
        raw_bytes: Vec::new(),
        source,
    }
}

fn ka_record(owner: &str, target: &str) -> browse::RawRecord {
    raw_record(owner, 12, "PTR", target, 120)
}

fn remote_source() -> std::net::SocketAddr {
    "192.168.1.99:5353".parse().unwrap()
}

/// Due continuous entry plus an 80%-aged PTR: active mode must
/// transmit on both timers, passive mode on neither.
fn due_query_setup() -> App {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(120));
    ingest(&mut app, &srv_record(120));
    for svc in &mut app.services {
        for rec in &mut svc.answers {
            if rec.rtype == 12 {
                rec.received_at = Instant::now() - Duration::from_secs(100);
            }
        }
    }
    app.scheduler.continuous_mut().insert(
        ("_http._tcp.local".to_string(), 12),
        ContinuousQuery {
            next_due: Instant::now() - Duration::from_millis(1),
            interval: Duration::from_secs(2),
            qname: "_http._tcp.local".to_string(),
        },
    );
    app
}

/// Text content of a rendered rect, rows joined by newline.
fn rect_text(buf: &ratatui::buffer::Buffer, area: ratatui::layout::Rect) -> String {
    let mut out = String::new();
    for y in area.y..area.y.saturating_add(area.height) {
        for x in area.x..area.x.saturating_add(area.width) {
            if let Some(cell) = buf.cell((x, y)) {
                out.push_str(cell.symbol());
            }
        }
        out.push('\n');
    }
    out
}

/// A live Test._http._tcp.local service on host test.local.
fn test_service_app() -> App {
    let mut app = App::new().unwrap();
    ingest(&mut app, &ptr_record(4500));
    ingest(&mut app, &srv_record(120));
    app
}

fn findings_of(app: &App, kind: anomalies::AnomalyKind) -> Vec<anomalies::Anomaly> {
    app.anomalies()
        .into_iter()
        .filter(|a| a.kind == kind)
        .collect()
}

const DACP: &str = "iTunes_Ctrl._dacp._tcp.local.";

const SMB: &str = "KNULP._smb._tcp.local.";

fn packet(records: Vec<browse::RawRecord>) -> browse::Event {
    browse::Event {
        answers: records,
        questions: Vec::new(),
        query_kas: Vec::new(),
        rcode: Some(0),
        received_at: Instant::now(),
        raw_bytes: Vec::new(),
        source: test_source(),
    }
}

fn srv_on_knulp(instance: &str) -> browse::RawRecord {
    let mut srv = raw_record(instance, 33, "SRV", "0 0 3689 knulp.local.", 120);
    srv.flush_bit = true;
    srv
}

fn aaaa_knulp() -> browse::RawRecord {
    raw_record("knulp.local.", 28, "AAAA", "fd00::1", 120)
}

fn a_knulp() -> browse::RawRecord {
    raw_record("knulp.local.", 1, "A", "192.168.178.27", 120)
}

/// `_dacp` and `_smb` both on knulp.local; avahi's AAAA already filed.
fn knulp_app() -> App {
    let mut app = App::new().unwrap();
    for (ty, inst) in [("_dacp._tcp.local.", DACP), ("_smb._tcp.local.", SMB)] {
        ingest(&mut app, &raw_record(ty, 12, "PTR", inst, 4500));
        ingest(&mut app, &srv_on_knulp(inst));
    }
    ingest(&mut app, &aaaa_knulp());
    app
}

/// The service of `instance`, given bare (`Test`) or as its full
/// `instance.service_type` (`Test._http._tcp.local`). Matches the whole
/// name, so dotted instance labels and two types sharing an instance
/// label resolve to the right service.
fn service_of<'a>(app: &'a App, instance: &str) -> &'a ServiceEntry {
    let full = instance.trim_end_matches('.');
    // The full key wins over a bare instance label: a dotted instance
    // can spell another service's full name.
    let key = full.to_lowercase();
    app.services
        .iter()
        .find(|s| service_key(&s.instance, &s.service_type) == key)
        .or_else(|| app.services.iter().find(|s| s.instance == full))
        .unwrap_or_else(|| panic!("no service {instance}"))
}

/// Row types of a service's live rows: not a goodbye and not past TTL.
fn live_rows(app: &App, instance: &str) -> Vec<u16> {
    service_of(app, instance)
        .answers
        .iter()
        .filter(|r| record_liveness(r) == RecordLiveness::Live)
        .map(|r| r.rtype)
        .collect()
}

/// Row types of every row of a service, goodbye (TTL 0) rows included.
fn all_rows(app: &App, instance: &str) -> Vec<u16> {
    service_of(app, instance)
        .answers
        .iter()
        .map(|r| r.rtype)
        .collect()
}

fn legacy_aaaa_denial() -> browse::RawRecord {
    raw_record(DACP, 47, "NSEC", "iTunes_Ctrl._dacp._tcp.local. AAAA", 120)
}

/// Answers pane text, one line per table row (borders included).
fn answers_text(app: &App) -> Vec<String> {
    let buf = render_to_buffer(app, 160, 40);
    rect_text(&buf, app.layout.answers_rect.get())
        .lines()
        .map(str::to_string)
        .collect()
}

/// Whether a finding of `kind` sits in the block headed by line
/// `block` (before the next block or record row).
fn block_has(lines: &[String], block: usize, kind: &str) -> bool {
    lines[block + 1..]
        .iter()
        .take_while(|l| l.starts_with("│  "))
        .any(|l| l.contains(kind))
}

fn icon(severity: anomalies::Severity) -> char {
    App::anomaly_level_icon(severity)
}

/// The live service finding of `kind`, from the analyzer.
fn finding(app: &App, kind: anomalies::AnomalyKind) -> anomalies::Anomaly {
    app.anomalies()
        .into_iter()
        .find(|a| a.kind == kind)
        .unwrap_or_else(|| panic!("expected a {kind} finding"))
}

/// Findings the displayed target's Answers pane shows, each with the
/// record row it sits under (`None` inside a block).
fn shown(app: &App) -> Vec<(anomalies::Anomaly, Option<usize>)> {
    let Some(target) = app.display_detail() else {
        return Vec::new();
    };
    app.answers_layout(&target, &app.anomalies())
        .into_iter()
        .filter_map(|l| match l {
            AnswerLine::Finding { anomaly, record } => Some((*anomaly, record)),
            _ => None,
        })
        .collect()
}

/// The diagnostics overlay's `Anomalies` summary value.
fn summary(app: &App) -> String {
    let rows = app.diagnostics_rows();
    let at = rows
        .iter()
        .position(|(k, v)| k == "Anomalies" && v.is_empty())
        .expect("Anomalies section");
    rows[at + 1..]
        .iter()
        .find(|(k, _)| k == "summary")
        .map(|(_, v)| v.clone())
        .expect("summary row")
}

const BOX_V4: &str = "169.254.1.1:5353";

const BOX_LL: &str = "[fe80::7eff:4dff:fe15:7f88]:5353";

const REPEATER: &str = "192.168.178.109:5353";

fn from(mut rec: browse::RawRecord, source: &str) -> browse::RawRecord {
    rec.source = source.parse().unwrap();
    rec
}

/// The observed FRITZ! mesh: `Fritzel` points at `fritz.box`; the
/// main box announces `fritz.box AAAA fd00::…:7f88` (never its
/// link-local address), the repeater its own A record.
fn fritz_mesh() -> App {
    let mut app = App::new().unwrap();
    ingest(
        &mut app,
        &from(
            raw_record(
                "_fbox._tcp.local.",
                12,
                "PTR",
                "Fritzel._fbox._tcp.local.",
                4500,
            ),
            BOX_V4,
        ),
    );
    let mut srv = raw_record(
        "Fritzel._fbox._tcp.local.",
        33,
        "SRV",
        "0 0 49000 fritz.box.",
        120,
    );
    srv.flush_bit = true;
    ingest(&mut app, &from(srv, BOX_V4));
    ingest(
        &mut app,
        &from(
            raw_record("fritz.box.", 28, "AAAA", "fd00::7eff:4dff:fe15:7f88", 120),
            BOX_V4,
        ),
    );
    ingest(
        &mut app,
        &from(
            raw_record(
                "FritzBoxRepeater.fritz.box.",
                1,
                "A",
                "192.168.178.109",
                120,
            ),
            REPEATER,
        ),
    );
    app.evict_expired();
    app
}

const BOX_ULA: &str = "fd00::7eff:4dff:fe15:7f88";

const REP_ULA: &str = "fd00::ca0e:14ff:feff:416";

fn aaaa(host: &str, addr: &str, source: &str) -> browse::RawRecord {
    from(raw_record(host, 28, "AAAA", addr, 120), source)
}

fn conflicts(app: &App) -> Vec<anomalies::Anomaly> {
    findings_of(app, anomalies::AnomalyKind::ConflictingAnswers)
}

fn on_link(mut rec: browse::RawRecord, iface: &str, ifindex: u32) -> browse::RawRecord {
    rec.iface = iface.to_string();
    rec.ifindex = ifindex;
    rec
}

/// Answers rows (rendered) that carry `needle`.
fn rows_with(app: &App, needle: &str) -> Vec<String> {
    answers_text(app)
        .into_iter()
        .filter(|l| l.contains(needle))
        .collect()
}

fn addr(rtype: u16, ip: &str, source: &str) -> browse::RawRecord {
    let family = if rtype == 1 { "A" } else { "AAAA" };
    let mut rec = from(raw_record("test.local.", rtype, family, ip, 120), source);
    rec.flush_bit = true;
    rec.iface = "br0".into();
    rec.ifindex = 8;
    rec
}

fn querier(i: usize) -> SocketAddr {
    format!("192.168.{}.{}:5353", 1 + i / 200, 10 + i % 200)
        .parse()
        .unwrap()
}

fn ask(app: &mut App, name: &str, source: SocketAddr) {
    app.ingest_event(&query_event(name, 16, "TXT", false, Vec::new(), source));
}

/// The diagnostics overlay's value for `key`.
fn diagnostics_value(app: &App, key: &str) -> String {
    app.diagnostics_rows()
        .into_iter()
        .find(|(k, _)| k == key)
        .unwrap_or_else(|| panic!("no diagnostics row {key}"))
        .1
}

/// Press `code` without modifiers.
fn press(app: &mut App, code: crossterm::event::KeyCode) {
    press_with(app, code, crossterm::event::KeyModifiers::empty());
}

fn press_with(
    app: &mut App,
    code: crossterm::event::KeyCode,
    modifiers: crossterm::event::KeyModifiers,
) {
    use crossterm::event::{KeyEventKind, KeyEventState};
    app.handle_key(&KeyEvent {
        code,
        modifiers,
        kind: KeyEventKind::Press,
        state: KeyEventState::empty(),
    });
}

/// The whole frame as text, one line per terminal row.
fn screen(app: &App, width: u16, height: u16) -> Vec<String> {
    let buf = render_to_buffer(app, width, height);
    rect_text(&buf, buf.area)
        .lines()
        .map(str::to_string)
        .collect()
}

/// Whether a rendered line shows `key` with `value` next to it.
fn shows_row(lines: &[String], key: &str, value: &str) -> bool {
    lines.iter().any(|l| {
        l.split_once(key)
            .is_some_and(|(_, rest)| rest.trim_start().starts_with(value))
    })
}
