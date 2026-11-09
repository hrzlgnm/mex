use std::cell::Cell;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use crossterm::event::{self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers};
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

/// Continuous-browse state per (name, type), RFC 6762 §5.2: first query
/// after 20-120ms, then >=1s, doubling each time, capped at 1/hour.
struct ContinuousQuery {
    next_due: Instant,
    interval: Duration,
    /// Name as sent on the wire (original case). The map key is
    /// normalized to lowercase for host names so lookups dedup
    /// case-insensitively, but the query itself keeps wire case.
    qname: String,
}

/// Small xorshift-style helper so query jitter does not need a new
/// dependency. Seeded from wall-clock time plus an atomic counter.
fn rand_u32() -> u32 {
    static CTR: AtomicU64 = AtomicU64::new(0);
    let t = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs() ^ (d.subsec_nanos() as u64))
        .unwrap_or(0x9e3779b9);
    let c = CTR.fetch_add(0x9e3779b97f4a7c15, Ordering::Relaxed);
    let mut x = t.wrapping_add(c).wrapping_add(0x9e3779b97f4a7c15);
    x ^= x >> 30;
    x = x.wrapping_mul(0xbf58476d1ce4e5b9);
    x ^= x >> 27;
    x = x.wrapping_mul(0x94d049bb133111eb);
    x ^= x >> 31;
    (x >> 32) as u32
}

/// Inclusive random range for scheduling jitter.
fn rand_range(lo_ms: u64, hi_ms: u64) -> Duration {
    let span = hi_ms.saturating_sub(lo_ms).saturating_add(1).max(1);
    Duration::from_millis(lo_ms + (rand_u32() as u64 % span))
}

const ENUM_SERVICE: &str = "_services._dns-sd._udp.local";
/// Maximum interval between continuous queries (RFC 6762 §5.2 steady state).
const MAX_CONTINUOUS_INTERVAL: Duration = Duration::from_secs(3600);
/// Local address refresh is unrelated to querying; keep it on its own timer.
const LOCAL_IPS_REFRESH: Duration = Duration::from_secs(60);

pub struct App {
    pub services: Vec<ServiceEntry>,
    pub selected_display: usize,
    pub list_offset: Cell<usize>,
    pub detail_selected: usize,
    pub detail_offset: Cell<usize>,
    pub questions_offset: Cell<usize>,
    pub packet_count: u64,
    pub start_time: Instant,
    pub running: bool,

    rx: mpsc::Receiver<browse::Event>,
    query_tx: browse::QueryTx,
    /// Continuous browse schedule per (name, rtype): RFC 6762 §5.2
    /// exponential backoff (1s, 2s, 4s, … capped at 1h). Replaces the old
    /// fixed 60s re-poll. TTL-driven cache refresh lives in `requeries`.
    continuous: HashMap<(String, u16), ContinuousQuery>,
    /// Every service type ever learned (enumeration answers, PTR owners,
    /// confirmed services). Persistent: used for instance/type splitting
    /// and as the desired continuous-query set. Never cleared on a timer.
    known_types: HashSet<String>,
    /// Requery schedule per (name, type): (next query due, unanswered
    /// count). RFC 6762 §5.2: a querier SHOULD re-ask at 80% of the TTL,
    /// then 85/90/95% if no answer arrives, with ~2% random variation;
    /// after four misses the record expires at 100% (no hourly refresh —
    /// hourly is only the cap for *unanswered* continuous browsing).
    /// Known answers suppress the responses in between. Answers reset the
    /// schedule via push_record.
    requeries: HashMap<(String, u16), (Instant, u8)>,
    /// Enumeration answers learned from `_services._dns-sd._udp.local`
    /// PTR records: service type -> (original TTL, received_at, ingress
    /// interface). Used as known answers on enumeration requeries
    /// (RFC 6762 §7.1, shared), scoped to the link they came from.
    enum_known: HashMap<String, (u32, Instant, String)>,
    /// Whether the startup QU batch was already sent (RFC 6762 §5.4:
    /// QU only on wake/interface-activation batch, QM afterwards).
    startup_qu_sent: bool,
    last_ip_refresh: Instant,
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
            (&a.rtype_str, a.source.to_string(), &a.name, &a.rdata).cmp(&(
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
        let (query_tx, rx) = browse::spawn()?;
        Ok(Self {
            services: Vec::new(),
            selected_display: 0,
            list_offset: Cell::new(0),
            packet_count: 0,
            start_time: Instant::now(),
            running: true,
            rx,
            query_tx,
            continuous: HashMap::new(),
            known_types: HashSet::new(),
            requeries: HashMap::new(),
            enum_known: HashMap::new(),
            startup_qu_sent: false,
            last_ip_refresh: Instant::now(),
            collapsed_types: HashSet::new(),
            local_ips: browse::local_ips(),
            detail_selected: 0,
            detail_offset: Cell::new(0),
            questions_offset: Cell::new(0),
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
                        self.handle_key(&key);
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
            if self.packet_count > 0 && self.packet_count.is_multiple_of(10) {
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
                if self.services[j]
                    .hostname
                    .trim_end_matches('.')
                    .to_lowercase()
                    == host
                {
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
            self.raw_events
                .drain(0..self.raw_events.len().saturating_sub(2000));
        }

        for ev in &batch {
            self.ingest_event(ev);
        }
        self.flush_pending_addrs();
    }

    fn remaining_ttl(rec: &browse::RawRecord) -> u32 {
        rec.ttl
            .saturating_sub(rec.received_at.elapsed().as_secs() as u32)
    }

    /// Known PTR answers for a service type (or enumeration), RFC 6762 §7.1:
    /// only records with at least half of the original TTL remaining, sent
    /// with their remaining TTL so responders can suppress duplicates.
    /// Unique types (SRV/TXT/A/AAAA) are intentionally omitted: §7.1 notes
    /// known-answer suppression is for shared records. Each answer carries
    /// the interface it was observed on; the transport only sends it back
    /// out that same link, where it can actually suppress something.
    fn known_ptrs(&self, owner: &str) -> Vec<browse::KnownAnswer> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        let mut push_rec = |rec: &browse::RawRecord, out: &mut Vec<browse::KnownAnswer>| {
            if rec.rtype != 12 || rec.ttl == 0 {
                return;
            }
            let remaining = Self::remaining_ttl(rec);
            if remaining * 2 < rec.ttl {
                return;
            }
            let target = rec.rdata.trim_end_matches('.').to_string();
            if seen.insert((target.clone(), rec.iface.clone())) {
                out.push(browse::KnownAnswer {
                    target,
                    ttl: remaining,
                    iface: rec.iface.clone(),
                });
            }
        };
        for s in &self.services {
            if s.service_type != owner {
                continue;
            }
            for rec in &s.records {
                push_rec(rec, &mut out);
            }
        }
        for p in &self.pending_instances {
            if p.service_type != owner {
                continue;
            }
            for rec in &p.records {
                push_rec(rec, &mut out);
            }
        }
        out
    }

    fn known_enum_answers(&self) -> Vec<browse::KnownAnswer> {
        let now = Instant::now();
        let mut out = Vec::new();
        for (svc_type, (ttl, received, iface)) in &self.enum_known {
            let elapsed = now.duration_since(*received).as_secs() as u32;
            let remaining = ttl.saturating_sub(elapsed);
            if *ttl == 0 || remaining * 2 < *ttl {
                continue;
            }
            out.push(browse::KnownAnswer {
                target: svc_type.clone(),
                ttl: remaining,
                iface: iface.clone(),
            });
        }
        out
    }

    fn record_type_from_u16(rtype: u16) -> Option<RecordType> {
        match rtype {
            12 => Some(RecordType::PTR),
            33 => Some(RecordType::SRV),
            16 => Some(RecordType::TXT),
            1 => Some(RecordType::A),
            28 => Some(RecordType::AAAA),
            _ => None,
        }
    }

    fn requery_expiring(&mut self) {
        let now = Instant::now();
        // Per-key minimum TTL plus whether any row reached the 80% window.
        let mut ttl_by_key: HashMap<(String, u16), u32> = HashMap::new();
        let mut triggered: HashSet<(String, u16)> = HashSet::new();
        for svc in &self.services {
            for rec in &svc.records {
                if rec.ttl == 0 {
                    continue;
                }
                match rec.rtype {
                    12 | 33 | 16 | 1 | 28 => {}
                    _ => continue,
                }
                let key = (rec.name.trim_end_matches('.').to_string(), rec.rtype);
                ttl_by_key
                    .entry(key.clone())
                    .and_modify(|t| *t = (*t).min(rec.ttl))
                    .or_insert(rec.ttl);
                let elapsed = rec.received_at.elapsed().as_secs() as u32;
                if elapsed * 5 >= rec.ttl * 4 {
                    triggered.insert(key);
                }
            }
        }
        if triggered.is_empty() {
            return;
        }
        for key in triggered {
            let ttl = ttl_by_key.get(&key).copied().unwrap_or(120);
            // 0-2% random variation so queriers do not stay in lockstep
            // (RFC 6762 §5.2: 80-82%, 85-87%, 90-92%, 95-97%).
            let jitter_pct = rand_u32() % 201;
            // 5% of TTL plus jitter, floored at 1s (RFC 6762 §5.2 wants
            // >=1s between the first two queries).
            let step_millis = (ttl as u64) * 50 + (ttl as u64) * (jitter_pct as u64) / 10;
            let step = Duration::from_millis(step_millis.max(1000));
            let (due, count) = self.requeries.get(&key).copied().unwrap_or((now, 0));
            if count > 0 && now < due {
                continue;
            }
            let Some(rt) = Self::record_type_from_u16(key.1) else {
                continue;
            };
            let ka = if rt == RecordType::PTR {
                if key.0 == ENUM_SERVICE {
                    self.known_enum_answers()
                } else {
                    self.known_ptrs(&key.0)
                }
            } else {
                Vec::new()
            };
            self.query_tx.send(browse::QueryRequest {
                name: key.0.clone(),
                record_type: rt,
                known_answers: ka,
                qu: false,
            });
            let unanswered = (count + 1).min(4);
            if unanswered >= 4 {
                // RFC 6762 §5.2: after queries at ~80/85/90/95% with no
                // answer, the record expires at 100% — no hourly refresh.
                // Hourly is only the cap for unanswered *continuous*
                // browsing (see `continuous`), which keeps running.
                self.requeries.remove(&key);
            } else {
                self.requeries.insert(key, (now + step, unanswered));
            }
        }
    }

    /// Map key for `continuous`: host names (A/AAAA) are matched
    /// case-insensitively, everything else keeps wire case. The query
    /// itself always uses the original case (see `qname`).
    fn continuous_key(name: &str, rtype: u16) -> (String, u16) {
        if rtype == 1 || rtype == 28 {
            (name.to_lowercase(), rtype)
        } else {
            (name.to_string(), rtype)
        }
    }

    /// Desired continuous-browse queries: enumeration plus every live PTR /
    /// SRV / TXT / A / AAAA interest, as key -> wire-case name. Derived
    /// from live state each tick so dead services stop costing queries
    /// (RFC 6762 §5.2: no maintenance without active interest).
    fn desired_continuous(&self) -> HashMap<(String, u16), String> {
        let mut desired = HashMap::new();
        let mut want = |name: String, rtype: u16| {
            let key = Self::continuous_key(&name, rtype);
            desired.entry(key).or_insert(name);
        };
        want(ENUM_SERVICE.to_string(), 12);
        for t in &self.known_types {
            want(t.clone(), 12);
        }
        for p in &self.pending_instances {
            want(p.service_type.clone(), 12);
            let full = format!("{}.{}", p.instance, p.service_type);
            want(full.clone(), 33);
            want(full, 16);
        }
        for svc in &self.services {
            want(svc.service_type.clone(), 12);
            let full = format!("{}.{}", svc.instance, svc.service_type);
            want(full.clone(), 33);
            want(full, 16);
            if !svc.hostname.is_empty() {
                let host = svc.hostname.trim_end_matches('.').to_string();
                want(host.clone(), 1);
                want(host, 28);
            }
        }
        desired
    }

    fn poll_continuous(&mut self) {
        let now = Instant::now();
        let desired = self.desired_continuous();
        // Drop interests that went away (no queries without active interest).
        self.continuous.retain(|k, _| desired.contains_key(k));
        for (key, qname) in desired {
            let (due, send_name) = match self.continuous.get(&key) {
                Some(entry) => (now >= entry.next_due, entry.qname.clone()),
                None => {
                    // RFC 6762 §5.2: first query delayed 20-120ms random.
                    self.continuous.insert(
                        key.clone(),
                        ContinuousQuery {
                            next_due: now + rand_range(20, 120),
                            interval: Duration::from_secs(1),
                            qname: qname.clone(),
                        },
                    );
                    (false, qname)
                }
            };
            if !due {
                continue;
            }
            let Some(rt) = Self::record_type_from_u16(key.1) else {
                continue;
            };
            let ka = if rt == RecordType::PTR {
                if key.0 == ENUM_SERVICE {
                    self.known_enum_answers()
                } else {
                    self.known_ptrs(&send_name)
                }
            } else {
                Vec::new()
            };
            // QU only on the very first startup enumeration batch
            // (RFC 6762 §5.4); everything afterwards is QM.
            let qu = !self.startup_qu_sent && key.0 == ENUM_SERVICE && key.1 == 12;
            if qu {
                self.startup_qu_sent = true;
            }
            self.query_tx.send(browse::QueryRequest {
                name: send_name,
                record_type: rt,
                known_answers: ka,
                qu,
            });
            // RFC 6762 §5.2: at least 1s between the first two, then at
            // least doubling, capped at one query per hour.
            if let Some(entry) = self.continuous.get_mut(&key) {
                let next_interval = (entry.interval * 2).min(MAX_CONTINUOUS_INTERVAL);
                entry.interval = next_interval.max(Duration::from_secs(1));
                entry.next_due = now + entry.interval;
            }
        }
    }

    fn send_queries(&mut self) {
        self.flush_pending_addrs();
        // Learn service types before scheduling so new PTR owners are
        // browsed without waiting for a record-bearing service entry.
        for svc in &self.services {
            self.known_types.insert(svc.service_type.clone());
        }
        for p in &self.pending_instances {
            self.known_types.insert(p.service_type.clone());
        }
        for t in self.enum_known.keys() {
            self.known_types.insert(t.clone());
        }

        self.poll_continuous();
        self.requery_expiring();

        // Refresh in case interfaces/addresses changed (cheap: ~1 fork/min).
        // Independent of query backoff.
        if self.last_ip_refresh.elapsed() >= LOCAL_IPS_REFRESH {
            self.last_ip_refresh = Instant::now();
            self.local_ips = browse::local_ips();
        }
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
                None => groups.push(G {
                    label: s.service_type.clone(),
                    indices: vec![i],
                }),
            }
        }

        let mut items = Vec::new();
        groups.sort_by(|a, b| a.label.cmp(&b.label));
        for g in &groups {
            let mut sorted = g.indices.clone();
            sorted.sort_by(|&a, &b| self.services[a].instance.cmp(&self.services[b].instance));
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

    fn handle_key(&mut self, key: &KeyEvent) {
        // Ctrl+C quits: raw mode turns it into a key event (no SIGINT).
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.running = false;
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Left => self.set_collapsed(true),
            KeyCode::Right => self.set_collapsed(false),
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
                if cur == 0 {
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
            self.questions_offset.set(0);
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
    /// as an expired row instead of vanishing silently. PTR goodbyes name
    /// the type, so the withdrawn instance is matched via the rdata.
    fn ingest_goodbye(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let mut names = vec![rec.name.trim_end_matches('.').to_lowercase()];
        if rec.rtype == 12 {
            names.push(rec.rdata.trim_end_matches('.').to_lowercase());
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
            let inst = self.services[i].instance.to_lowercase();
            if names.iter().any(|n| *n == full || *n == host || *n == inst) {
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
            if full == name || host == name || self.services[i].service_type.to_lowercase() == name
            {
                let s = &mut self.services[i];
                match s.questions.iter().position(|(n, t, src, _, _)| {
                    n == &q.name && t == &q.rtype_str && src == &ev.source
                }) {
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
            12 => self.handle_ptr(rec, ev),
            33 => self.handle_srv(rec, ev),
            16 => self.handle_txt(rec),
            1 | 28 => self.handle_addr(rec, ev),
            _ => self.handle_other(rec, ev),
        }
    }

    fn handle_ptr(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let st = rec.name.trim_end_matches('.');
        let target = rec.rdata.trim_end_matches('.');

        if st == ENUM_SERVICE {
            // Track enumeration answers for known-answer suppression and
            // for the continuous browse set; polling itself runs through
            // the §5.2 backoff in poll_continuous.
            self.known_types.insert(target.to_string());
            if rec.ttl > 0 {
                self.enum_known.insert(
                    target.to_string(),
                    (rec.ttl, rec.received_at, rec.iface.clone()),
                );
            } else {
                self.enum_known.remove(target);
            }
            return;
        }

        if let Some(sub_pos) = st.find("._sub.") {
            let subtype = &st[..sub_pos];
            let svc_type = &st[sub_pos + 6..];
            let suffix = format!(".{svc_type}");
            let instance = target.strip_suffix(&suffix).unwrap_or(target);
            let pi = self.ensure_pending(instance, svc_type);
            if !self.pending_instances[pi]
                .subtypes
                .contains(&subtype.to_string())
            {
                self.pending_instances[pi]
                    .subtypes
                    .push(subtype.to_string());
            }
            self.pending_instances[pi].records.push(rec.clone());
            return;
        }

        let suffix = format!(".{st}");
        let instance = target.strip_suffix(&suffix).unwrap_or(target);
        let pi = self.ensure_pending(instance, st);
        self.pending_instances[pi].records.push(rec.clone());
        // A live PTR for an already-confirmed service must reactivate it
        // here: after a goodbye the service is inactive, and without this
        // forward the PTR would sit in pending until (and unless) a fresh
        // SRV arrives, leaving a returned service stuck offline.
        // push_record only reactivates on live PTR, so SRV/TXT answers
        // still cannot resurrect a withdrawn service.
        if let Some(idx) = self
            .services
            .iter()
            .position(|s| s.instance == instance && s.service_type == st)
        {
            self.services[idx].last_event = Some(ev.clone());
            self.push_record(idx, rec);
        }
    }

    /// Split a full instance name ("inst._svc._tcp.local") into (instance,
    /// service type). Instance names may legally contain dots (e.g. Fire TV
    /// style "amzn.dmgr:...:..."), so splitting on the first dot misparses
    /// them. Match against known service types instead (longest suffix
    /// wins); the caller falls back to the naive split when nothing is
    /// known yet. Case is preserved as-is since all candidates come from
    /// the same wire data.
    fn split_instance_type(&self, full_name: &str) -> Option<(String, String)> {
        let mut best: Option<(String, String)> = None;
        let mut consider = |known: &str| {
            if known.is_empty() {
                return;
            }
            if let Some(instance) = full_name
                .strip_suffix(known)
                .and_then(|prefix| prefix.strip_suffix('.'))
            {
                if instance.is_empty() {
                    return;
                }
                let replace = match &best {
                    Some((_, current)) => known.len() > current.len(),
                    None => true,
                };
                if replace {
                    best = Some((instance.to_string(), known.to_string()));
                }
            }
        };
        for s in &self.services {
            consider(&s.service_type);
        }
        for p in &self.pending_instances {
            consider(&p.service_type);
        }
        for t in &self.known_types {
            consider(t);
        }
        for t in self.enum_known.keys() {
            consider(t);
        }
        best
    }

    fn handle_srv(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let name = rec.name.trim_end_matches('.');
        let (instance, service_type) = match self.split_instance_type(name) {
            Some(split) => split,
            None => {
                let parts: Vec<&str> = name.splitn(2, '.').collect();
                if parts.len() < 2 {
                    return;
                }
                (parts[0].to_string(), parts[1].to_string())
            }
        };
        let idx = self.ensure_svc(&instance, &service_type);

        let sv: Vec<&str> = rec.rdata.split_whitespace().collect();
        if sv.len() >= 4 {
            self.services[idx].port = sv[2].parse().unwrap_or(0);
            self.services[idx].hostname = sv[3..].join(" ");
        }
        self.push_record(idx, rec);
        self.services[idx].last_event = Some(ev.clone());

        // merge any cached data from pending_instances, routing each
        // record through push_record so live PTRs reactivate a returned
        // service (and replace their goodbye rows) instead of duplicating
        // them via a blind extend.
        let svc_idx = idx;
        let mut i = 0;
        while i < self.pending_instances.len() {
            if self.pending_instances[i].instance == instance
                && self.pending_instances[i].service_type == service_type
            {
                let p = self.pending_instances.swap_remove(i);
                for sub in p.subtypes {
                    if !self.services[svc_idx].subtypes.contains(&sub) {
                        self.services[svc_idx].subtypes.push(sub);
                    }
                }
                self.services[svc_idx].last_seen =
                    self.services[svc_idx].last_seen.max(p.last_seen);
                let records = p.records;
                for rec in &records {
                    self.push_record(svc_idx, rec);
                }
            } else {
                i += 1;
            }
        }
    }

    fn handle_txt(&mut self, rec: &browse::RawRecord) {
        let name = rec.name.trim_end_matches('.');
        let (instance, service_type) = match self.split_instance_type(name) {
            Some(split) => split,
            None => {
                let parts: Vec<&str> = name.splitn(2, '.').collect();
                if parts.len() < 2 {
                    return;
                }
                (parts[0].to_string(), parts[1].to_string())
            }
        };
        let pi = self.ensure_pending(&instance, &service_type);

        self.pending_instances[pi].records.push(rec.clone());
    }

    fn handle_addr(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let host = rec.name.trim_end_matches('.').to_lowercase();
        for i in 0..self.services.len() {
            if self.services[i]
                .hostname
                .trim_end_matches('.')
                .to_lowercase()
                == host
            {
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
            let full = format!(
                "{}.{}",
                self.services[i].instance, self.services[i].service_type
            )
            .to_lowercase();
            if full == name
                || self.services[i]
                    .hostname
                    .trim_end_matches('.')
                    .to_lowercase()
                    == name
            {
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
        if rec.ttl > 0 && rec.rtype == 12 {
            // Only a live PTR (re)announcement puts the service back on
            // the browse list. Answers to our own SRV re-queries must not
            // resurrect a withdrawn service: the phone is still on the
            // network and answers, but it no longer browses the service.
            // TTL 0 goodbyes pass through without reactivating; mark_goodbye
            // runs first anyway.
            s.is_active = true;
        }
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
        // Fresh answer resets the RFC 6762 §5.2 requery schedule, but only
        // if no row for this key is still inside the 80%-TTL window:
        // sibling rows with other rdata/sources may still need their
        // backoff, and clearing on every unrelated answer re-arms the
        // trigger each loop iteration (reset-driven storm).
        if rec.ttl > 0 {
            let key = (rec.name.trim_end_matches('.').to_string(), rec.rtype);
            let still_expiring = self.services[svc_idx].records.iter().any(|r| {
                r.ttl > 0
                    && r.name.trim_end_matches('.') == key.0.as_str()
                    && r.rtype == key.1
                    && r.received_at.elapsed().as_secs() as u32 * 5 >= r.ttl * 4
            });
            if !still_expiring {
                self.requeries.remove(&key);
            }
            // RFC 6762 §5.2: a unique answer (cache-flush bit) means no
            // other answers are forthcoming, so dampen the exponential
            // discovery stream and let the 80%-TTL refresh take over.
            if rec.flush_bit {
                let ckey = Self::continuous_key(rec.name.trim_end_matches('.'), rec.rtype);
                if let Some(entry) = self.continuous.get_mut(&ckey) {
                    entry.interval = MAX_CONTINUOUS_INTERVAL;
                    entry.next_due = Instant::now() + MAX_CONTINUOUS_INTERVAL;
                }
            }
        }
    }

    /// Flip a service inactive when a goodbye names it. For a PTR goodbye
    /// the withdrawn instance is the rdata (base-type withdrawal, e.g. a
    /// phone stopping its share), so match that too. DNS names are
    /// case-insensitive.
    fn mark_goodbye(&mut self, rec: &browse::RawRecord) {
        let mut candidates = vec![rec.name.trim_end_matches('.').to_lowercase()];
        if rec.rtype == 12 {
            candidates.push(rec.rdata.trim_end_matches('.').to_lowercase());
        }
        for svc in &mut self.services {
            let full = format!("{}.{}", svc.instance, svc.service_type).to_lowercase();
            if candidates
                .iter()
                .any(|n| n == &full || n == &svc.instance.to_lowercase())
            {
                svc.is_active = false;
                return;
            }
        }
    }

    /// Flip services with no live browse (PTR) record left to inactive
    /// (with a fresh last_seen, granting the usual grace period), so a
    /// withdrawn service reads as gone even while its SRV keeps getting
    /// answered. Services never enumerated (no PTR rows yet) fall back to
    /// any-record liveness. Re-announced PTRs reactivate via push_record.
    fn expire_stale_services(services: &mut [ServiceEntry]) {
        let now = Instant::now();
        let is_live = |r: &browse::RawRecord| r.ttl > r.received_at.elapsed().as_secs() as u32;
        for svc in services.iter_mut() {
            if !svc.is_active || svc.records.is_empty() {
                continue;
            }
            let has_ptr = svc.records.iter().any(|r| r.rtype == 12);
            let gone = if has_ptr {
                !svc.records.iter().any(|r| r.rtype == 12 && is_live(r))
            } else {
                !svc.records.iter().any(is_live)
            };
            if gone {
                svc.is_active = false;
                svc.last_seen = now;
            }
        }
    }

    fn evict_expired(&mut self) {
        let grace = Duration::from_secs(120);
        let now = Instant::now();
        Self::expire_stale_services(&mut self.services);
        self.services
            .retain(|s| s.is_active || now.duration_since(s.last_seen) < grace);
        self.pending_instances
            .retain(|p| now.duration_since(p.last_seen) < grace);
        // Drop schedules for names that no longer exist, so dead services
        // stop costing even an hourly query (RFC 6762 §5.2: no maintenance
        // without active interest).
        let mut live: HashSet<(String, u16)> = HashSet::new();
        live.insert((ENUM_SERVICE.to_string(), 12));
        for svc in &self.services {
            live.insert((svc.service_type.clone(), 12));
            let full = format!("{}.{}", svc.instance, svc.service_type);
            live.insert((full.clone(), 33));
            live.insert((full, 16));
            if !svc.hostname.is_empty() {
                let host = svc.hostname.trim_end_matches('.').to_lowercase();
                live.insert((host.clone(), 1));
                live.insert((host, 28));
            }
            for rec in &svc.records {
                live.insert((rec.name.trim_end_matches('.').to_string(), rec.rtype));
            }
        }
        for p in &self.pending_instances {
            live.insert((p.service_type.clone(), 12));
            let full = format!("{}.{}", p.instance, p.service_type);
            live.insert((full.clone(), 33));
            live.insert((full, 16));
        }
        for t in self.enum_known.keys() {
            live.insert((t.clone(), 12));
        }
        self.requeries.retain(|k, _| live.contains(k));
        self.continuous.retain(|k, _| live.contains(k));
        // Expire enumeration known answers at 100% TTL; prune the type
        // cache to live interests so it cannot grow without bound.
        self.enum_known
            .retain(|_, (ttl, received, _)| received.elapsed().as_secs() as u32 <= *ttl);
        let live_types: HashSet<String> = live
            .iter()
            .filter(|(_, t)| *t == 12)
            .map(|(n, _)| n.clone())
            .collect();
        self.known_types.retain(|t| live_types.contains(t));
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
        // The first header is not a selectable stop, so plain
        // follow-the-cursor scrolling would strand the viewport at
        // offset 1 with row 0 hidden forever. When the cursor sits on
        // the first selectable row, pull the view back to the top.
        if let Some(first) = items.iter().position(|it| self.is_selectable(it)) {
            if self.selected_display == first {
                let top = first.saturating_sub(1);
                if self.list_offset.get() > top {
                    self.list_offset.set(top);
                }
            }
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
        self.is_local_source(&rec.source)
    }

    pub fn is_local_source(&self, source: &std::net::SocketAddr) -> bool {
        self.local_ips.contains(&source.ip())
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
            .find(|s| s.service_type == key.0 && s.instance == key.1)
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::SocketAddr;

    fn test_source() -> SocketAddr {
        "192.168.1.2:5353".parse().unwrap()
    }

    fn raw_record(
        name: &str,
        rtype: u16,
        rtype_str: &str,
        rdata: &str,
        ttl: u32,
    ) -> browse::RawRecord {
        browse::RawRecord {
            name: name.to_string(),
            rtype,
            rtype_str: rtype_str.to_string(),
            flush_bit: false,
            ttl,
            rdata: rdata.to_string(),
            wire: Vec::new(),
            source: test_source(),
            iface: String::new(),
            received_at: Instant::now(),
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
        raw_record(
            "Test._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 test.local.",
            ttl,
        )
    }

    fn event_for(rec: &browse::RawRecord) -> browse::Event {
        browse::Event {
            records: vec![rec.clone()],
            questions: Vec::new(),
            raw_bytes: Vec::new(),
            source: test_source(),
        }
    }

    fn ingest(app: &mut App, rec: &browse::RawRecord) {
        let ev = event_for(rec);
        app.ingest_event(&ev);
    }

    fn live_ptr_rows(app: &App) -> Vec<browse::RawRecord> {
        app.services
            .iter()
            .flat_map(|s| s.ordered_records())
            .filter(|r| r.rtype == 12)
            .cloned()
            .collect()
    }

    #[test]
    fn record_carries_ingress_interface() {
        let mut app = App::new().unwrap();
        let mut rec = ptr_record(120);
        rec.iface = "br0".to_string();
        ingest(&mut app, &rec);
        ingest(&mut app, &srv_record(120));
        let ptrs = live_ptr_rows(&app);
        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0].iface, "br0");
    }

    #[test]
    fn known_answers_carry_their_ingress_interface() {
        let mut app = App::new().unwrap();
        let mut a = ptr_record(120);
        a.iface = "br0".to_string();
        ingest(&mut app, &a);
        // Same instance seen on another link: distinct source, distinct row.
        let mut b = ptr_record(120);
        b.iface = "enx".to_string();
        b.source = "192.168.178.61:5353".parse().unwrap();
        ingest(&mut app, &b);
        ingest(&mut app, &srv_record(120));
        let mut ifaces: Vec<String> = app
            .known_ptrs("_http._tcp.local")
            .into_iter()
            .map(|ka| ka.iface)
            .collect();
        ifaces.sort();
        assert_eq!(ifaces, vec!["br0".to_string(), "enx".to_string()]);
    }

    #[test]
    fn hostname_case_preserved_in_queries() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(
            &mut app,
            &raw_record(
                "Test._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 MyHost.local.",
                120,
            ),
        );
        // Dedup keys stay lowercase, but the query name keeps wire case.
        let desired = app.desired_continuous();
        let qname = desired
            .get(&("myhost.local".to_string(), 1))
            .expect("A query interest for the host");
        assert_eq!(qname.trim_end_matches('.'), "MyHost.local");
        let qname_aaaa = desired
            .get(&("myhost.local".to_string(), 28))
            .expect("AAAA query interest for the host");
        assert_eq!(qname_aaaa.trim_end_matches('.'), "MyHost.local");
    }

    #[test]
    fn goodbye_then_comeback_reactivates() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        assert_eq!(app.services.len(), 1);
        assert!(app.services[0].is_active);

        // Goodbye takes the service offline but keeps it during grace.
        ingest(&mut app, &ptr_record(0));
        assert_eq!(app.services.len(), 1);
        assert!(!app.services[0].is_active);

        // Comeback with valid TTL must show the service as online again.
        ingest(&mut app, &ptr_record(120));
        assert!(app.services[0].is_active);
        let ptrs = live_ptr_rows(&app);
        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0].ttl, 120);

        // A fresh SRV burst merges pending state without duplicating the
        // PTR row or dropping back offline.
        ingest(&mut app, &srv_record(120));
        assert!(app.services[0].is_active);
        let ptrs = live_ptr_rows(&app);
        assert_eq!(ptrs.len(), 1);
        assert_eq!(ptrs[0].ttl, 120);
    }
}
