use std::cell::Cell;
use std::collections::HashSet;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEventKind};
use hickory_proto::rr::RecordType;

use crate::browse;
use crate::ui;

#[derive(Clone)]
pub enum DisplayItem {
    ServiceType { label: String },
    Instance { index: usize },
}

/// Row selected by the j/k cursor in the Records table.
pub enum DetailEntry<'a> {
    Record(&'a browse::RawRecord),
    Question {
        name: &'a str,
        rtype_str: &'a str,
        raw: &'a [u8],
    },
}

/// Identity of the cursor row, so the selection survives resorting of the
/// table (TTL countdowns and re-announcements constantly reshuffle rows).
/// Matches the dedup identities used at ingest.
#[derive(Clone, PartialEq, Eq)]
enum DetailCursorKey {
    Record {
        name: String,
        rtype: u16,
        rdata: String,
        source: std::net::SocketAddr,
    },
    Question {
        name: String,
        rtype: String,
        source: std::net::SocketAddr,
    },
}

struct PendingService {
    instance: String,
    service_type: String,
    records: Vec<browse::RawRecord>,
    subtypes: Vec<String>,
    last_seen: Instant,
}

pub struct App {
    pub services: Vec<ServiceEntry>,
    pub selected_display: usize,
    pub list_offset: Cell<usize>,
    pub detail_selected: usize,
    pub detail_offset: Cell<usize>,
    pub packet_count: u64,
    pub start_time: Instant,
    pub running: bool,

    rx: mpsc::Receiver<browse::Event>,
    query_tx: mpsc::Sender<browse::QueryRequest>,
    last_query: Instant,
    burst_count: u8,
    queried_types: HashSet<String>,
    queried_instances: HashSet<String>,
    queried_hosts: HashSet<String>,
    collapsed_types: HashSet<String>,
    local_ips: HashSet<std::net::IpAddr>,
    detail_svc_key: Option<(String, String)>,
    detail_anchor: Option<DetailCursorKey>,
    sticky_key: Option<(String, String)>,
    pending_instances: Vec<PendingService>,
    pending_addrs: Vec<(String, browse::RawRecord)>,
    pub raw_events: Vec<browse::Event>,
}

pub struct ServiceEntry {
    pub instance: String,
    pub service_type: String,
    pub hostname: String,
    pub port: u16,
    pub subtypes: Vec<String>,
    pub records: Vec<browse::RawRecord>,
    /// Recently seen questions asking for this service:
    /// (name, type, querier, received_at, query packet bytes). Capped.
    pub questions: Vec<(String, String, std::net::SocketAddr, Instant, Vec<u8>)>,
    pub last_seen: Instant,
    pub is_active: bool,
    /// Most recent packet that touched this service; the right panes fall
    /// back to it once the shared event buffer has moved on.
    pub last_event: Option<browse::Event>,
}

impl ServiceEntry {
    /// Raw records deduped by name/type/rdata/source (latest wins), sorted by
    /// type then source for display. Same record announced by different
    /// responders counts as distinct observations, grouped adjacently.
    /// Mirrors the replace identity used by `push_record`.
    pub fn ordered_records(&self) -> Vec<&browse::RawRecord> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for rec in self.records.iter().rev() {
            if seen.insert((&rec.name, rec.rtype, &rec.rdata, rec.source)) {
                out.push(rec);
            }
        }
        out.sort_by(|a, b| {
            (
                &a.rtype_str,
                a.source.to_string(),
                &a.name,
                &a.rdata,
            )
                .cmp(&(
                    &b.rtype_str,
                    b.source.to_string(),
                    &b.name,
                    &b.rdata,
                ))
        });
        out
    }
}

impl App {
    pub fn new() -> Result<Self> {
        let (query_tx, query_rx) = mpsc::channel();
        let rx = browse::spawn(query_rx)?;
        Ok(Self {
            services: Vec::new(),
            selected_display: 0,
            list_offset: Cell::new(0),
            packet_count: 0,
            start_time: Instant::now(),
            running: true,
            rx,
            query_tx,
            last_query: Instant::now() - Duration::from_secs(10),
            burst_count: 0,
            queried_types: HashSet::new(),
            queried_instances: HashSet::new(),
            queried_hosts: HashSet::new(),
            collapsed_types: HashSet::new(),
            local_ips: browse::local_ips(),
            detail_selected: 0,
            detail_offset: Cell::new(0),
            detail_svc_key: None,
            detail_anchor: None,
            sticky_key: None,
            pending_instances: Vec::new(),
            pending_addrs: Vec::new(),
            raw_events: Vec::new(),
        })
    }

    pub fn run(&mut self, terminal: &mut Option<ui::Terminal>) -> Result<()> {
        if let Some(term) = terminal.as_mut() {
            self.run_tui(term)?;
        } else {
            self.run_headless()?;
        }
        Ok(())
    }

    fn run_tui(&mut self, terminal: &mut ui::Terminal) -> Result<()> {
        while self.running {
            self.drain_events();
            self.send_queries();
            self.evict_expired();

            terminal.draw(|f| ui::draw(f, self))?;

            if event::poll(Duration::from_millis(80))? {
                if let Event::Key(key) = event::read()? {
                    if key.kind == KeyEventKind::Press {
                        self.handle_key(key.code);
                    }
                }
            }
        }
        Ok(())
    }

    fn run_headless(&mut self) -> Result<()> {
        eprintln!("mex: started (no TUI available, listening on port 5353)");
        while self.running {
            self.drain_events();
            self.send_queries();
            if self.packet_count > 0 && self.packet_count % 10 == 0 {
                eprintln!(
                    "mex: {} packets, {} services seen",
                    self.packet_count,
                    self.services.len()
                );
            }
            self.evict_expired();
            std::thread::sleep(Duration::from_millis(1000));
        }
        Ok(())
    }

    fn flush_pending_addrs(&mut self) {
        let mut i = 0;
        while i < self.pending_addrs.len() {
            let host = self.pending_addrs[i].0.clone();
            let rec = self.pending_addrs[i].1.clone();
            let mut matched = false;
            for j in 0..self.services.len() {
                if self.services[j].hostname.trim_end_matches('.').to_lowercase() == host {
                    self.push_record(j, &rec);
                    matched = true;
                    break;
                }
            }
            if matched {
                self.pending_addrs.swap_remove(i);
            } else {
                i += 1;
            }
        }
    }

    fn drain_events(&mut self) {
        let mut batch: Vec<browse::Event> = Vec::new();
        while let Ok(ev) = self.rx.try_recv() {
            self.packet_count += 1;
            batch.push(ev);
        }

        for ev in &batch {
            self.raw_events.push(ev.clone());
        }
        if self.raw_events.len() > 2000 {
            self.raw_events.drain(0..self.raw_events.len().saturating_sub(2000));
        }

        for ev in &batch {
            self.ingest_event(ev);
        }
        self.flush_pending_addrs();
    }

    fn known_ptrs(&self, svc_type: &str) -> Vec<(String, u32)> {
        let mut out = Vec::new();
        for s in &self.services {
            if s.service_type != svc_type {
                continue;
            }
            for rec in &s.records {
                if rec.rtype == 12 {
                    out.push((rec.rdata.clone(), rec.ttl));
                }
            }
        }
        for p in &self.pending_instances {
            if p.service_type != svc_type {
                continue;
            }
            for rec in &p.records {
                if rec.rtype == 12 {
                    out.push((rec.rdata.clone(), rec.ttl));
                }
            }
        }
        out
    }

    fn requery_expiring(&self) {
        let mut seen = std::collections::HashSet::new();
        for svc in &self.services {
            for rec in &svc.records {
                if rec.ttl == 0 { continue; }
                let elapsed = rec.received_at.elapsed().as_secs() as u32;
                if elapsed * 5 >= rec.ttl * 4 {
                    let name = rec.name.trim_end_matches('.').to_string();
                    let query = match rec.rtype {
                        12 => Some((name, RecordType::PTR)),
                        33 => Some((name, RecordType::SRV)),
                        16 => Some((name, RecordType::TXT)),
                        1 => Some((name, RecordType::A)),
                        28 => Some((name, RecordType::AAAA)),
                        _ => None,
                    };
                    if let Some((n, rt)) = query {
                        if seen.insert((n.clone(), rt)) {
                            let ka = if rt == RecordType::PTR {
                                self.known_ptrs(&n)
                            } else {
                                Vec::new()
                            };
                            let _ = self.query_tx.send(browse::QueryRequest {
                                name: n,
                                record_type: rt,
                                known_answers: ka,
                            });
                        }
                    }
                }
            }
        }
    }

    fn send_queries(&mut self) {
        self.flush_pending_addrs();
        let now = Instant::now();

        // pending instances (PTR seen, SRV pending)
        for p in &self.pending_instances {
            if self.queried_types.insert(p.service_type.clone()) {
                let _ = self.query_tx.send(browse::QueryRequest {
                    name: p.service_type.clone(),
                    record_type: RecordType::PTR,
                    known_answers: self.known_ptrs(&p.service_type),
                });
            }
            let full = format!("{}.{}", p.instance, p.service_type);
            if self.queried_instances.insert(full.clone()) {
                let _ = self.query_tx.send(browse::QueryRequest {
                    name: full.clone(),
                    record_type: RecordType::SRV,
                    known_answers: Vec::new(),
                });
                let _ = self.query_tx.send(browse::QueryRequest {
                    name: full,
                    record_type: RecordType::TXT,
                    known_answers: Vec::new(),
                });
            }
        }

        for svc in &self.services {
            // new service type → PTR for its instances
            if self.queried_types.insert(svc.service_type.clone()) {
                let _ = self.query_tx.send(browse::QueryRequest {
                    name: svc.service_type.clone(),
                    record_type: RecordType::PTR,
                    known_answers: self.known_ptrs(&svc.service_type),
                });
            }
            // re-query SRV + TXT for confirmed services
            let full = format!("{}.{}", svc.instance, svc.service_type);
            if self.queried_instances.insert(full.clone()) {
                let _ = self.query_tx.send(browse::QueryRequest {
                    name: full.clone(),
                    record_type: RecordType::SRV,
                    known_answers: Vec::new(),
                });
                let _ = self.query_tx.send(browse::QueryRequest {
                    name: full,
                    record_type: RecordType::TXT,
                    known_answers: Vec::new(),
                });
            }
            // new host → A + AAAA
            if !svc.hostname.is_empty() {
                let host = svc.hostname.trim_end_matches('.').to_lowercase();
                if self.queried_hosts.insert(host.clone()) {
                    let _ = self.query_tx.send(browse::QueryRequest {
                        name: host.clone(),
                        record_type: RecordType::A,
                        known_answers: Vec::new(),
                    });
                    let _ = self.query_tx.send(browse::QueryRequest {
                        name: host,
                        record_type: RecordType::AAAA,
                        known_answers: Vec::new(),
                    });
                }
            }
        }

        self.requery_expiring();

        // RFC 6762: initial burst (3 queries ~1s apart), then every 60 s
        let interval = if self.burst_count < 3 { 1u64 } else { 60 };
        let elapsed = now.duration_since(self.last_query).as_secs();
        if elapsed < interval {
            return;
        }
        self.last_query = now;
        self.burst_count = self.burst_count.saturating_add(1);

        self.queried_types.clear();
        self.queried_instances.clear();
        self.queried_hosts.clear();
        // Refresh in case interfaces/addresses changed (cheap: ~1 fork/min).
        self.local_ips = browse::local_ips();

        let _ = self.query_tx.send(browse::QueryRequest {
            name: "_services._dns-sd._udp.local".into(),
            record_type: RecordType::PTR,
            known_answers: Vec::new(),
        });
    }

    pub fn display_items(&self) -> Vec<DisplayItem> {
        struct G {
            label: String,
            indices: Vec<usize>,
        }

        let mut groups: Vec<G> = Vec::new();
        for (i, s) in self.services.iter().enumerate() {
            match groups.iter_mut().find(|g| g.label == s.service_type) {
                Some(g) => g.indices.push(i),
                None => groups.push(G { label: s.service_type.clone(), indices: vec![i] }),
            }
        }

        let mut items = Vec::new();
        groups.sort_by(|a, b| a.label.cmp(&b.label));
        for g in &groups {
            let mut sorted = g.indices.clone();
            sorted.sort_by(|&a, &b| {
                self.services[a].instance.cmp(&self.services[b].instance)
            });
            items.push(DisplayItem::ServiceType {
                label: g.label.clone(),
            });
            if self.collapsed_types.contains(&g.label) {
                continue;
            }
            for idx in sorted {
                items.push(DisplayItem::Instance { index: idx });
            }
        }
        items
    }

    fn toggle_collapse(&mut self) {
        let items = self.display_items();
        match items.get(self.selected_display) {
            Some(DisplayItem::ServiceType { label }) => {
                let label = label.clone();
                if !self.collapsed_types.remove(&label) {
                    self.collapsed_types.insert(label);
                }
            }
            // Hostname is folded into the instance row, so Space on an
            // instance folds its parent service type.
            Some(DisplayItem::Instance { index }) => {
                let label = self.services[*index].service_type.clone();
                if !self.collapsed_types.remove(&label) {
                    self.collapsed_types.insert(label);
                }
            }
            None => {}
        }
        self.clamp_selection();
    }

    /// Directional fold for Left (collapse) / Right (expand). Operates on
    /// the service type of the cursor row (own type, or the parent type
    /// for an instance row).
    fn set_collapsed(&mut self, collapse: bool) {
        let label = match self.display_items().get(self.selected_display) {
            Some(DisplayItem::ServiceType { label }) => Some(label.clone()),
            Some(DisplayItem::Instance { index }) => {
                Some(self.services[*index].service_type.clone())
            }
            None => None,
        };
        if let Some(label) = label {
            if collapse {
                self.collapsed_types.insert(label);
            } else {
                self.collapsed_types.remove(&label);
            }
        }
        self.clamp_selection();
    }

    fn handle_key(&mut self, code: KeyCode) {
        match code {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Left => self.set_collapsed(true),
            KeyCode::Right => self.set_collapsed(false),
            KeyCode::Char('c') => {
                self.services.clear();
                self.selected_display = 0;
                self.sticky_key = None;
                self.detail_svc_key = None;
                self.detail_anchor = None;
                self.detail_selected = 0;
                self.detail_offset.set(0);
            }
            KeyCode::Char('R') => self.raw_events.clear(),
            // Record cursor, only meaningful while the Records table is shown.
            KeyCode::Char('j') => self.move_detail_cursor(1),
            KeyCode::Char('k') => self.move_detail_cursor(-1),
            KeyCode::Char(' ') | KeyCode::Enter | KeyCode::Char('+') | KeyCode::Char('-') => {
                self.toggle_collapse()
            }
            _ => {}
        }
    }

    /// Selectable stops for Up/Down: instances always, service-type
    /// headers only while collapsed (so a collapsed type can be
    /// uncollapsed again; folding is also available from member rows).
    fn is_selectable(&self, item: &DisplayItem) -> bool {
        match item {
            DisplayItem::Instance { .. } => true,
            DisplayItem::ServiceType { label } => self.collapsed_types.contains(label),
        }
    }

    fn move_selection(&mut self, delta: isize) {
        let items = self.display_items();
        if items.is_empty() {
            self.selected_display = 0;
            return;
        }
        let max = items.len().saturating_sub(1);
        let mut cur = self.selected_display;

        // Service-type headers are not stops; Up/Down lands on instances.
        loop {
            if delta > 0 {
                if cur >= max {
                    break;
                }
                cur += 1;
            } else if delta < 0 {
                if cur <= 0 {
                    break;
                }
                cur -= 1;
            } else {
                break;
            }
            if self.is_selectable(&items[cur]) {
                self.selected_display = cur;
                return;
            }
        }
    }

    /// j/k cursor over the Records table rows: raw records first, then
    /// questions. The cursor tracks row identity, so TTL resorting and
    /// re-announcements don't yank the selection to another row.
    fn move_detail_cursor(&mut self, delta: isize) {
        self.sync_detail_cursor();
        let total = self
            .display_service()
            .map(|s| s.ordered_records().len() + s.questions.len())
            .unwrap_or(0);
        let max = total.saturating_sub(1);
        if delta > 0 {
            if self.detail_selected < max {
                self.detail_selected += 1;
            }
        } else if delta < 0 && self.detail_selected > 0 {
            self.detail_selected -= 1;
        }
        self.detail_anchor = self
            .display_service()
            .and_then(|svc| Self::identity_at(svc, self.detail_selected));
    }

    /// Identity of the table row at an index (raw records first, then
    /// questions newest-first, matching the rendered table).
    fn identity_at(svc: &ServiceEntry, index: usize) -> Option<DetailCursorKey> {
        let raws = svc.ordered_records();
        if index < raws.len() {
            let r = raws[index];
            return Some(DetailCursorKey::Record {
                name: r.name.clone(),
                rtype: r.rtype,
                rdata: r.rdata.clone(),
                source: r.source,
            });
        }
        svc.questions
            .iter()
            .rev()
            .nth(index - raws.len())
            .map(|(name, rtype, source, _, _)| DetailCursorKey::Question {
                name: name.clone(),
                rtype: rtype.clone(),
                source: *source,
            })
    }

    /// Index of the row with an identity, if still present.
    fn position_of(svc: &ServiceEntry, key: &DetailCursorKey) -> Option<usize> {
        let raws = svc.ordered_records();
        match key {
            DetailCursorKey::Record {
                name,
                rtype,
                rdata,
                source,
            } => raws.iter().position(|r| {
                &r.name == name && r.rtype == *rtype && &r.rdata == rdata && r.source == *source
            }),
            DetailCursorKey::Question {
                name,
                rtype,
                source,
            } => svc
                .questions
                .iter()
                .rev()
                .position(|(n, t, src, _, _)| n == name && t == rtype && src == source)
                .map(|pos| pos + raws.len()),
        }
    }

    /// Keep the detail cursor pointed at the displayed service, resetting to
    /// the first entry when the service changes (or disappears) and
    /// re-anchoring the index to the tracked identity otherwise. Headers
    /// select nothing, so they leave the cursor (and sticky service) alone.
    fn sync_detail_cursor(&mut self) {
        let key = self
            .selected_service()
            .map(|s| (s.service_type.clone(), s.instance.clone()));
        if key.is_none() {
            return;
        }
        if self.detail_svc_key != key {
            self.detail_svc_key = key;
            self.detail_selected = 0;
            self.detail_offset.set(0);
            self.detail_anchor = self
                .selected_service()
                .and_then(|svc| Self::identity_at(svc, self.detail_selected));
            return;
        }
        // Re-anchor the index to the tracked identity; rows reshuffle as
        // TTLs tick and re-announcements land.
        let anchor = self.detail_anchor.clone();
        let pos = self
            .display_service()
            .and_then(|svc| anchor.as_ref().and_then(|a| Self::position_of(svc, a)));
        match (pos, anchor) {
            (Some(pos), _) => self.detail_selected = pos,
            (None, Some(_)) => {
                // Tracked row expired away (capped question list): park on
                // the last raw record instead of pointing at shifted churn.
                let parked = self
                    .display_service()
                    .map(|s| s.ordered_records().len().saturating_sub(1))
                    .unwrap_or(0);
                self.detail_selected = parked;
                self.detail_anchor = self
                    .display_service()
                    .and_then(|svc| Self::identity_at(svc, self.detail_selected));
            }
            (None, None) => {}
        }
        // Clamp against entries that aged away (capped question list).
        let max = self
            .selected_service()
            .map(|s| (s.ordered_records().len() + s.questions.len()).saturating_sub(1))
            .unwrap_or(0);
        if self.detail_selected > max {
            self.detail_selected = max;
        }
    }

    fn ingest_event(&mut self, ev: &browse::Event) {
        for rec in &ev.records {
            if rec.ttl == 0 {
                self.mark_goodbye(rec);
                self.ingest_goodbye(rec, ev);
                continue;
            }
            self.ingest_record(rec, ev);
        }
        for q in &ev.questions {
            self.route_question(q, ev);
        }
    }

    /// File a goodbye (TTL 0) record with the matching service so it renders
    /// as an expired row instead of vanishing silently.
    fn ingest_goodbye(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let name = rec.name.trim_end_matches('.').to_lowercase();
        for i in 0..self.services.len() {
            let full = format!(
                "{}.{}",
                self.services[i].instance, self.services[i].service_type
            )
            .to_lowercase();
            let host = self.services[i]
                .hostname
                .trim_end_matches('.')
                .to_lowercase();
            if full == name || host == name || self.services[i].instance.to_lowercase() == name {
                self.services[i].last_event = Some(ev.clone());
                self.push_record(i, rec);
                return;
            }
        }
    }

    /// File a question asking for a service, so the Records view can show
    /// who is asking (and the hex pane can show the query packet).
    /// The enumeration query is network noise, skip it.
    fn route_question(&mut self, q: &browse::RawRecord, ev: &browse::Event) {
        let name = q.name.trim_end_matches('.').to_lowercase();
        if name == "_services._dns-sd._udp.local" {
            return;
        }
        for i in 0..self.services.len() {
            let full = format!(
                "{}.{}",
                self.services[i].instance, self.services[i].service_type
            )
            .to_lowercase();
            let host = self.services[i]
                .hostname
                .trim_end_matches('.')
                .to_lowercase();
            if full == name
                || host == name
                || self.services[i].service_type.to_lowercase() == name
            {
                let s = &mut self.services[i];
                match s.questions.iter().position(
                    |(n, t, src, _, _)| n == &q.name && t == &q.rtype_str && src == &ev.source,
                ) {
                    Some(pos) => {
                        s.questions[pos] = (
                            q.name.clone(),
                            q.rtype_str.clone(),
                            ev.source,
                            q.received_at,
                            ev.raw_bytes.clone(),
                        );
                    }
                    None => {
                        s.questions.push((
                            q.name.clone(),
                            q.rtype_str.clone(),
                            ev.source,
                            q.received_at,
                            ev.raw_bytes.clone(),
                        ));
                        if s.questions.len() > 10 {
                            s.questions.remove(0);
                        }
                    }
                }
            }
        }
    }

    fn ingest_record(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        match rec.rtype {
            12 => self.handle_ptr(rec),
            33 => self.handle_srv(rec, ev),
            16 => self.handle_txt(rec),
            1 | 28 => self.handle_addr(rec, ev),
            _ => self.handle_other(rec, ev),
        }
    }

    fn handle_ptr(&mut self, rec: &browse::RawRecord) {
        let st = rec.name.trim_end_matches('.');
        let target = rec.rdata.trim_end_matches('.');

        if st == "_services._dns-sd._udp.local" {
            if self.queried_types.insert(target.to_string()) {
                let _ = self.query_tx.send(browse::QueryRequest {
                    name: target.to_string(),
                    record_type: RecordType::PTR,
                    known_answers: self.known_ptrs(target),
                });
            }
            return;
        }

        if let Some(sub_pos) = st.find("._sub.") {
            let subtype = &st[..sub_pos];
            let svc_type = &st[sub_pos + 6..];
            let suffix = format!(".{svc_type}");
            let instance = target.strip_suffix(&suffix).unwrap_or(target);
            let pi = self.ensure_pending(instance, svc_type);
            if !self.pending_instances[pi].subtypes.contains(&subtype.to_string()) {
                self.pending_instances[pi].subtypes.push(subtype.to_string());
            }
            self.pending_instances[pi].records.push(rec.clone());
            return;
        }

        let suffix = format!(".{st}");
        let instance = target.strip_suffix(&suffix).unwrap_or(target);
        let pi = self.ensure_pending(instance, st);
        self.pending_instances[pi].records.push(rec.clone());
    }

    fn handle_srv(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let name = rec.name.trim_end_matches('.');
        let parts: Vec<&str> = name.splitn(2, '.').collect();
        if parts.len() < 2 {
            return;
        }
        let idx = self.ensure_svc(parts[0], parts[1]);

        let sv: Vec<&str> = rec.rdata.split_whitespace().collect();
        if sv.len() >= 4 {
            self.services[idx].port = sv[2].parse().unwrap_or(0);
            self.services[idx].hostname = sv[3..].join(" ").to_lowercase();
        }
        self.push_record(idx, rec);
        self.services[idx].last_event = Some(ev.clone());

        // merge any cached data from pending_instances
        let svc_idx = idx;
        let mut i = 0;
        while i < self.pending_instances.len() {
            if self.pending_instances[i].instance == parts[0]
                && self.pending_instances[i].service_type == parts[1]
            {
                let p = self.pending_instances.swap_remove(i);
                let s = &mut self.services[svc_idx];
                s.records.extend(p.records);
                s.subtypes.extend(p.subtypes);
                s.last_seen = s.last_seen.max(p.last_seen);
            } else {
                i += 1;
            }
        }
    }

    fn handle_txt(&mut self, rec: &browse::RawRecord) {
        let name = rec.name.trim_end_matches('.');
        let parts: Vec<&str> = name.splitn(2, '.').collect();
        if parts.len() < 2 {
            return;
        }
        let pi = self.ensure_pending(parts[0], parts[1]);

        self.pending_instances[pi].records.push(rec.clone());
    }

    fn handle_addr(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let host = rec.name.trim_end_matches('.').to_lowercase();
        for i in 0..self.services.len() {
            if self.services[i].hostname.trim_end_matches('.').to_lowercase() == host {
                self.services[i].last_event = Some(ev.clone());
                self.push_record(i, rec);
                return;
            }
        }
        self.pending_addrs.push((host, rec.clone()));
    }

    fn handle_other(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let name = rec.name.trim_end_matches('.').to_lowercase();
        for i in 0..self.services.len() {
            let full = format!("{}.{}", self.services[i].instance, self.services[i].service_type).to_lowercase();
            if full == name || self.services[i].hostname.trim_end_matches('.').to_lowercase() == name {
                self.services[i].last_event = Some(ev.clone());
                self.push_record(i, rec);
                return;
            }
        }
    }

    fn ensure_pending(&mut self, instance: &str, service_type: &str) -> usize {
        for (i, p) in self.pending_instances.iter().enumerate() {
            if p.instance == instance && p.service_type == service_type {
                self.pending_instances[i].last_seen = Instant::now();
                return i;
            }
        }
        let i = self.pending_instances.len();
        self.pending_instances.push(PendingService {
            instance: instance.to_string(),
            service_type: service_type.to_string(),
            records: Vec::new(),
            subtypes: Vec::new(),
            last_seen: Instant::now(),
        });
        i
    }

    fn ensure_svc(&mut self, instance: &str, service_type: &str) -> usize {
        let now = Instant::now();
        for (i, s) in self.services.iter().enumerate() {
            if s.instance == instance && s.service_type == service_type {
                self.services[i].last_seen = now;
                return i;
            }
        }
        self.services.push(ServiceEntry {
            instance: instance.to_string(),
            service_type: service_type.to_string(),
            hostname: String::new(),
            port: 0,
            subtypes: Vec::new(),
            records: Vec::new(),
            questions: Vec::new(),
            last_seen: now,
            is_active: true,
            last_event: None,
        });
        self.services.len() - 1
    }

    fn push_record(&mut self, svc_idx: usize, rec: &browse::RawRecord) {
        let s = &mut self.services[svc_idx];
        s.last_seen = Instant::now();
        // replace stale record with same name+rtype+rdata+source to keep list clean
        if let Some(pos) = s.records.iter().position(|r| {
            r.name == rec.name
                && r.rtype == rec.rtype
                && r.rdata == rec.rdata
                && r.source == rec.source
        }) {
            s.records[pos] = rec.clone();
        } else {
            s.records.push(rec.clone());
        }
    }

    fn mark_goodbye(&mut self, rec: &browse::RawRecord) {
        let name = rec.name.trim_end_matches('.');
        for svc in &mut self.services {
            let full = format!("{}.{}", svc.instance, svc.service_type);
            if full == name || svc.instance == name {
                svc.is_active = false;
                return;
            }
        }
    }

    fn evict_expired(&mut self) {
        let grace = Duration::from_secs(120);
        let now = Instant::now();
        self.services.retain(|s| s.is_active || now.duration_since(s.last_seen) < grace);
        self.pending_instances.retain(|p| now.duration_since(p.last_seen) < grace);
        self.clamp_selection();
    }

    fn clamp_selection(&mut self) {
        let items = self.display_items();
        let max = items.len().saturating_sub(1);
        if self.selected_display > max {
            self.selected_display = max;
        }
        // Expanded headers are not selectable stops (e.g. after a collapse
        // stranded the cursor on one, or at startup); settle on an instance.
        // Collapsed headers stay put so their type can be unfolded again.
        if matches!(
            self.display_items().get(self.selected_display),
            Some(DisplayItem::ServiceType { label }) if !self.is_type_collapsed(label)
        ) {
            self.move_selection(1);
        }
        if matches!(
            self.display_items().get(self.selected_display),
            Some(DisplayItem::ServiceType { label }) if !self.is_type_collapsed(label)
        ) {
            self.move_selection(-1);
        }
        if self.selected_display < self.list_offset.get() {
            self.list_offset.set(self.selected_display);
        }
        if self.list_offset.get() > max {
            self.list_offset.set(max.saturating_sub(1));
        }
        // Sticky detail: headers select nothing, so remember the last
        // selected service to keep the right panes alive while navigating.
        let key = self
            .selected_service()
            .map(|s| (s.service_type.clone(), s.instance.clone()));
        if key.is_some() {
            self.sticky_key = key;
        }
        self.sync_detail_cursor();
    }

    pub fn is_type_collapsed(&self, label: &str) -> bool {
        self.collapsed_types.contains(label)
    }

    pub fn is_local_record(&self, rec: &browse::RawRecord) -> bool {
        self.local_ips.contains(&rec.source.ip())
    }

    pub fn service_type_count(&self, label: &str) -> usize {
        self.services
            .iter()
            .filter(|s| s.service_type == label)
            .count()
    }

    pub fn selected_service(&self) -> Option<&ServiceEntry> {
        let items = self.display_items();
        match items.get(self.selected_display)? {
            DisplayItem::Instance { index } => self.services.get(*index),
            _ => None,
        }
    }

    pub fn latest_event_for_selected(&self) -> Option<&browse::Event> {
        // Newest record first, then the service's last-seen packet: the
        // shared buffer ages with total traffic, so a quiet service's
        // packets may all be gone while its records live on.
        let svc = self.display_service()?;
        for rec in svc.records.iter().rev() {
            if let Some(ev) = self
                .raw_events
                .iter()
                .rev()
                .find(|ev| ev.source == rec.source)
            {
                return Some(ev);
            }
        }
        svc.last_event.as_ref()
    }

    /// Service shown in the right panes: the selected one, or the last
    /// selected one while the cursor sits on a service-type header.
    pub fn display_service(&self) -> Option<&ServiceEntry> {
        if let Some(svc) = self.selected_service() {
            return Some(svc);
        }
        let key = self.sticky_key.as_ref()?;
        self.services
            .iter()
            .find(|s| &s.service_type == &key.0 && &s.instance == &key.1)
    }

    /// Entry under the j/k cursor in the Records table: a raw record row or
    /// a question row (table order is raw records first, then questions
    /// newest-first, matching the rendered table).
    pub fn selected_detail_entry(&self) -> Option<DetailEntry<'_>> {
        let svc = self.display_service()?;
        let key = (svc.service_type.clone(), svc.instance.clone());
        if self.detail_svc_key.as_ref() != Some(&key) {
            return None;
        }
        let raws = svc.ordered_records();
        if self.detail_selected < raws.len() {
            return Some(DetailEntry::Record(raws[self.detail_selected]));
        }
        svc.questions
            .iter()
            .rev()
            .nth(self.detail_selected - raws.len())
            .map(|(name, rtype, _, _, raw)| DetailEntry::Question {
                name,
                rtype_str: rtype,
                raw,
            })
    }

    /// Hex dump payload for the hex pane: wire bytes of the selected record,
    /// or the stored query packet for a selected question row.
    pub fn selected_detail_bytes(&self) -> Option<(Vec<u8>, String)> {
        match self.selected_detail_entry()? {
            DetailEntry::Record(rec) => {
                if rec.wire.is_empty() {
                    return None;
                }
                Some((
                    rec.wire.clone(),
                    format!(" {} {} ", rec.rtype_str, rec.name),
                ))
            }
            DetailEntry::Question {
                name,
                rtype_str,
                raw,
            } => Some((raw.to_vec(), format!(" QRY {rtype_str} {name} "))),
        }
    }
}
