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
const LOCAL_IPS_REFRESH: Duration = Duration::from_secs(10);

/// Cache-refresh spacing: 5% of the TTL plus 0-2% random variation, so
/// queries land at ~80/85/90/95% with 80-82/85-87/90-92/95-97% jitter
/// (RFC 6762 §5.2). No 1s floor: the >=1s rule governs the continuous
/// stream, while refresh must still hit its windows for small TTLs.
fn refresh_step(ttl_secs: u32, jitter_pct: u32) -> Duration {
    let step_millis = (ttl_secs as u64) * 50 + (ttl_secs as u64) * (jitter_pct as u64) / 10;
    Duration::from_millis(step_millis.max(1))
}

/// How long an overheard QM query suppresses our own duplicate (RFC 6762
/// §7.3). Checked only when our query is due, so this is the window for
/// near-simultaneous queries from multiple queriers.
const OVERHEARD_WINDOW: Duration = Duration::from_secs(2);

pub struct App {
    pub services: Vec<ServiceEntry>,
    pub selected_display: usize,
    pub list_offset: Cell<usize>,
    /// Visible rows of the service list pane (minus borders), recorded
    /// during draw so PageUp/PageDown paging matches the viewport.
    pub list_viewport: Cell<usize>,
    pub detail_selected: usize,
    pub detail_offset: Cell<usize>,
    /// Manual scroll of the Answers table (`Ctrl-j/k`): while set, the
    /// viewport stays where the user put it instead of following the
    /// `j/k` cursor, so arbitrarily tall TXT expansions can be paged
    /// through. Any cursor or fold action clears it.
    pub detail_free_scroll: bool,
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
    /// Expanded TXT records in the Answers table, keyed by
    /// (name, rdata, source). Absent = collapsed (the default), so
    /// multi-pair TXT rows render as a single `▸ TXT` line until
    /// `Enter` expands them into `▾ TXT` plus child rows.
    expanded_txt: HashSet<(String, String, std::net::SocketAddr)>,
    local_ips: HashSet<std::net::IpAddr>,
    /// Recently overheard QM questions from other queriers (RFC 6762 §7.3):
    /// key (lowercased name, type) -> (seen_at, remote KA targets lowercased
    /// and dot-trimmed, ingress iface). Consumed to suppress our own
    /// duplicate once; pruned after OVERHEARD_WINDOW. Own loopback and QU
    /// questions are never stored.
    overheard: HashMap<(String, u16), (Instant, HashSet<String>, String)>,
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

    /// Questions sorted by type, then newest first — mirroring how answers
    /// sort by type. Reverse age keeps the freshest query for each type on
    /// top while the cursor identity (name/type/source) stays stable.
    pub fn ordered_questions(
        &self,
    ) -> Vec<&(String, String, std::net::SocketAddr, Instant, Vec<u8>)> {
        let mut out: Vec<_> = self.questions.iter().collect();
        out.sort_by(|a, b| {
            (&a.1, std::cmp::Reverse(a.3), a.2.to_string(), &a.0).cmp(&(
                &b.1,
                std::cmp::Reverse(b.3),
                b.2.to_string(),
                &b.0,
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
            list_viewport: Cell::new(0),
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
            expanded_txt: HashSet::new(),
            local_ips: browse::local_ips(),
            overheard: HashMap::new(),
            detail_selected: 0,
            detail_offset: Cell::new(0),
            detail_free_scroll: false,
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
        log::info!("mex: started (no TUI available, listening on port 5353)");
        while self.running {
            self.drain_events();
            self.send_queries();
            if self.packet_count > 0 && self.packet_count.is_multiple_of(10) {
                log::info!(
                    "mex: {} packets, {} services seen",
                    self.packet_count,
                    self.services.len()
                );
            }
            self.evict_expired();
            // Short tick like the TUI loop so the RFC 6762 §5.2 20-120ms
            // first-query delay is not quantized to a full second.
            std::thread::sleep(Duration::from_millis(50));
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
        // Per-key minimum TTL plus whether any *live* row reached the 80%
        // window. Expired rows (elapsed > TTL) are not refreshed: RFC 6762
        // §5.2 deletes the record at 100% after four unanswered queries.
        let mut ttl_by_key: HashMap<(String, u16), u32> = HashMap::new();
        let mut triggered: HashSet<(String, u16)> = HashSet::new();
        let mut live_keys: HashSet<(String, u16)> = HashSet::new();
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
                let elapsed = rec.received_at.elapsed().as_secs() as u32;
                if elapsed > rec.ttl {
                    continue;
                }
                live_keys.insert(key.clone());
                ttl_by_key
                    .entry(key.clone())
                    .and_modify(|t| *t = (*t).min(rec.ttl))
                    .or_insert(rec.ttl);
                if elapsed * 5 >= rec.ttl * 4 {
                    triggered.insert(key);
                }
            }
        }
        // Drop refresh schedules whose rows all expired: no maintenance
        // without a live record (RFC 6762 §5.2 deletes at 100%).
        self.requeries.retain(|k, _| live_keys.contains(k));
        if triggered.is_empty() {
            return;
        }
        for key in triggered {
            let ttl = ttl_by_key.get(&key).copied().unwrap_or(120);
            // 0-2% random variation so queriers do not stay in lockstep
            // (RFC 6762 §5.2: 80-82%, 85-87%, 90-92%, 95-97%). No 1s floor
            // here: the >=1s rule applies to the continuous stream, while
            // refresh spacing is 5% of the TTL (floors would push small
            // TTLs past 100%).
            let jitter_pct = rand_u32() % 201;
            let step = refresh_step(ttl, jitter_pct);
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
            // RFC 6762 §7.3: another querier just asked the same QM
            // question with no KA we wouldn't send — count ours as sent.
            if self.suppressed_by_overheard(&key, &ka) {
                self.postpone_continuous_for_refresh(&key, now);
                let unanswered = (count + 1).min(4);
                if unanswered >= 4 {
                    self.requeries.remove(&key);
                } else {
                    self.requeries.insert(key, (now + step, unanswered));
                }
                continue;
            }
            self.query_tx.send(browse::QueryRequest {
                name: key.0.clone(),
                record_type: rt,
                known_answers: ka,
                qu: false,
            });
            // A refresh query also elicits new answers, so postpone the
            // exponential stream for the same question: otherwise the two
            // timers can fire on the same tick and emit back-to-back
            // duplicates (RFC 6762 §5.2 spacing).
            self.postpone_continuous_for_refresh(&key, now);
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
            // RFC 6762 §7.3: another querier just asked the same QM
            // question with no KA we wouldn't send — treat ours as sent.
            // QU elicits unicast and is never suppressed.
            if !qu && self.suppressed_by_overheard(&key, &ka) {
                let now = Instant::now();
                self.advance_continuous(&key, now);
                continue;
            }
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
            // least doubling, capped at one query per hour. Send using the
            // current interval, then double for the following gap, so the
            // stream is 1s, 2s, 4s, ... (doubling before use would skip
            // the 1s gap and start at 2s).
            self.advance_continuous(&key, now);
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

        self.requery_expiring();
        self.poll_continuous();

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
            // Hostname is folded into the instance row, so +/- on an
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

    fn handle_key(&mut self, key: &KeyEvent) {
        // Ctrl+C quits: raw mode turns it into a key event (no SIGINT).
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.running = false;
            return;
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            // Detail viewport scroll (sibling: Shift+Up/Down, J/K).
            KeyCode::Up | KeyCode::Down
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    || key.modifiers.contains(KeyModifiers::SHIFT) =>
            {
                self.scroll_detail(if key.code == KeyCode::Down { 1 } else { -1 })
            }
            KeyCode::Char('j') | KeyCode::Char('k')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.scroll_detail(if key.code == KeyCode::Char('j') {
                    1
                } else {
                    -1
                })
            }
            KeyCode::Char('J') => self.scroll_detail(1),
            KeyCode::Char('K') => self.scroll_detail(-1),
            // Service selection (sibling: j/k + up/down).
            KeyCode::Up => self.move_selection(-1),
            KeyCode::Down => self.move_selection(1),
            KeyCode::Char('k') => self.move_selection(-1),
            KeyCode::Char('j') => self.move_selection(1),
            // Record cursor over the Answers table.
            KeyCode::Tab => self.move_detail_cursor(1),
            KeyCode::BackTab => self.move_detail_cursor(-1),
            // Service-type group jumps (sibling: h/l and arrows switch types).
            KeyCode::Char('h') | KeyCode::Left => self.jump_group(-1),
            KeyCode::Char('l') | KeyCode::Right => self.jump_group(1),
            // Shift jumps to the first/last group (uppercase from Shift).
            KeyCode::Char('H') => self.jump_group_edge(true),
            KeyCode::Char('L') => self.jump_group_edge(false),
            KeyCode::Home => self.select_edge(true),
            KeyCode::End => self.select_edge(false),
            KeyCode::PageUp | KeyCode::Char('b') => self.page_selection(-1),
            KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => self.page_selection(1),
            // Enter folds/unfolds the TXT record under the Tab cursor;
            // anywhere else it folds the service type like +/- does.
            KeyCode::Enter => {
                if !self.toggle_txt_expanded() {
                    self.toggle_collapse()
                }
            }
            KeyCode::Char('+') | KeyCode::Char('-') => self.toggle_collapse(),
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

    /// First/last selectable stop (sibling: Home/End).
    fn select_edge(&mut self, first: bool) {
        let items = self.display_items();
        let mut target = None;
        for (i, it) in items.iter().enumerate() {
            if self.is_selectable(it) {
                if first {
                    target = Some(i);
                    break;
                }
                target = Some(i);
            }
        }
        if let Some(i) = target {
            self.selected_display = i;
        }
    }

    /// Page the service selection by one viewport of stops (sibling:
    /// PageUp/PageDown/b/f/Space). Falls back to 10 stops before the
    /// first draw records the real height.
    fn page_selection(&mut self, pages: isize) {
        let per_page = self.list_viewport.get().max(1) as isize;
        let steps = pages * per_page;
        let n = steps.unsigned_abs().min(1000);
        for _ in 0..n {
            let before = self.selected_display;
            self.move_selection(steps.signum());
            if self.selected_display == before {
                break;
            }
        }
    }

    /// Service-type group labels in display order.
    fn group_labels(&self) -> Vec<String> {
        let mut labels = Vec::new();
        for it in self.display_items() {
            if let DisplayItem::ServiceType { label } = it {
                if !labels.contains(&label) {
                    labels.push(label);
                }
            }
        }
        labels
    }

    /// Label of the group containing the cursor row.
    fn cursor_group(&self) -> Option<String> {
        match self.display_items().get(self.selected_display)? {
            DisplayItem::ServiceType { label } => Some(label.clone()),
            DisplayItem::Instance { index } => Some(self.services[*index].service_type.clone()),
        }
    }

    /// Jump to the neighbouring type group (sibling: h/l switch types):
    /// lands on its first selectable stop.
    fn jump_group(&mut self, delta: isize) {
        let labels = self.group_labels();
        if labels.is_empty() {
            return;
        }
        let cur = self
            .cursor_group()
            .and_then(|g| labels.iter().position(|l| l == &g));
        let next = match cur {
            Some(i) if delta > 0 => (i + 1).min(labels.len() - 1),
            Some(i) if delta < 0 => i.saturating_sub(1),
            _ => {
                if delta > 0 {
                    0
                } else {
                    labels.len() - 1
                }
            }
        };
        self.select_group_first(&labels[next]);
    }

    /// Jump to the first/last type group (Shift+h/l).
    fn jump_group_edge(&mut self, first: bool) {
        let labels = self.group_labels();
        if labels.is_empty() {
            return;
        }
        let label = if first {
            &labels[0]
        } else {
            &labels[labels.len() - 1]
        };
        self.select_group_first(label);
    }

    /// Select the first selectable stop of a group: its header while
    /// collapsed, otherwise its first instance row.
    fn select_group_first(&mut self, label: &str) {
        let items = self.display_items();
        for (i, it) in items.iter().enumerate() {
            let belongs = match it {
                DisplayItem::ServiceType { label: l } => l == label,
                DisplayItem::Instance { index } => self
                    .services
                    .get(*index)
                    .is_some_and(|s| s.service_type == label),
            };
            if belongs && self.is_selectable(it) {
                self.selected_display = i;
                return;
            }
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

    /// Tab cursor over the Records table rows: raw records first, then
    /// questions. The cursor tracks row identity, so TTL resorting and
    /// re-announcements don't yank the selection to another row.
    fn move_detail_cursor(&mut self, delta: isize) {
        self.sync_detail_cursor();
        // Resuming cursor-follow: manual scroll ends once the cursor moves.
        self.detail_free_scroll = false;
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

    /// Nudge the Answers viewport without moving the `j/k` cursor, and pin
    /// it there until the cursor, selection, or expansion changes. Upper
    /// clamping happens at render time, where the row count is known.
    fn scroll_detail(&mut self, delta: isize) {
        let cur = self.detail_offset.get();
        let next = if delta < 0 {
            cur.saturating_sub(delta.unsigned_abs())
        } else {
            cur.saturating_add(delta.unsigned_abs())
        };
        self.detail_offset.set(next);
        self.detail_free_scroll = true;
    }

    /// Identity of the table row at an index (raw records first, then
    /// questions by type/newest-first, matching the rendered table).
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
        svc.ordered_questions()
            .into_iter()
            .nth(index - raws.len())
            .map(|q| DetailCursorKey::Question {
                name: q.0.clone(),
                rtype: q.1.clone(),
                source: q.2,
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
                .ordered_questions()
                .iter()
                .position(|q| q.0 == *name && q.1 == *rtype && q.2 == *source)
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
            self.detail_free_scroll = false;
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
            self.note_overheard(q, ev);
            self.route_question(q, ev);
        }
    }

    /// Record an overheard QM question for duplicate question suppression
    /// (RFC 6762 §7.3). Own loopback and QU questions are never stored.
    /// The remote Known-Answer set is stored dot-trimmed and lowercased;
    /// the subset check runs at send time against the KA we would send.
    fn note_overheard(&mut self, q: &browse::RawRecord, ev: &browse::Event) {
        if q.qu {
            return;
        }
        if self.is_local_source(&ev.source) {
            return;
        }
        let key = (q.name.trim_end_matches('.').to_lowercase(), q.rtype);
        let mut remote = HashSet::new();
        for ka in &ev.query_kas {
            if ka.rtype == q.rtype && ka.name.eq_ignore_ascii_case(&q.name) {
                remote.insert(ka.rdata.trim_end_matches('.').to_lowercase());
            }
        }
        self.overheard
            .insert(key, (Instant::now(), remote, q.iface.clone()));
    }

    /// RFC 6762 §7.3: if we overheard the same QM question recently and its
    /// Known-Answer section holds nothing we wouldn't send ourselves,
    /// treat our query as sent. Consumes the entry so one overheard query
    /// suppresses one transmission. `local_ka` is the KA list we computed
    /// for the send; filtering is scoped to the link the overheard query
    /// arrived on.
    fn suppressed_by_overheard(
        &mut self,
        key: &(String, u16),
        local_ka: &[browse::KnownAnswer],
    ) -> bool {
        let lookup = (key.0.trim_end_matches('.').to_lowercase(), key.1);
        let (seen, remote, iface) = match self.overheard.get(&lookup) {
            Some(v) => v.clone(),
            None => return false,
        };
        if seen.elapsed() >= OVERHEARD_WINDOW {
            return false;
        }
        let mut local = HashSet::new();
        for ka in local_ka {
            if ka.iface.is_empty() || iface.is_empty() || ka.iface == iface {
                local.insert(ka.target.trim_end_matches('.').to_lowercase());
            }
        }
        if remote.iter().all(|r| local.contains(r)) {
            self.overheard.remove(&lookup);
            return true;
        }
        false
    }

    /// Advance the exponential stream as if a query had been sent (shared
    /// by real sends and §7.3 suppression).
    fn advance_continuous(&mut self, key: &(String, u16), now: Instant) {
        if let Some(entry) = self.continuous.get_mut(key) {
            let current = entry.interval.max(Duration::from_secs(1));
            entry.next_due = now + current;
            entry.interval = (current * 2).min(MAX_CONTINUOUS_INTERVAL);
        }
    }

    /// Postpone the exponential stream after a refresh (real or suppressed)
    /// so the two §5.2 timers don't emit back-to-back duplicates.
    fn postpone_continuous_for_refresh(&mut self, key: &(String, u16), now: Instant) {
        let mut postponed = false;
        for (ckey, entry) in self.continuous.iter_mut() {
            if ckey.1 == key.1 && ckey.0.eq_ignore_ascii_case(&key.0) {
                let floor = now + entry.interval.max(Duration::from_secs(1));
                if entry.next_due < floor {
                    entry.next_due = floor;
                }
                postponed = true;
            }
        }
        if !postponed {
            let ckey = Self::continuous_key(&key.0, key.1);
            if let std::collections::hash_map::Entry::Vacant(e) = self.continuous.entry(ckey) {
                e.insert(ContinuousQuery {
                    next_due: now + Duration::from_secs(1),
                    interval: Duration::from_secs(1),
                    qname: key.0.clone(),
                });
            }
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
                if r.ttl == 0 || r.name.trim_end_matches('.') != key.0.as_str() || r.rtype != key.1
                {
                    return false;
                }
                let elapsed = r.received_at.elapsed().as_secs() as u32;
                elapsed <= r.ttl && elapsed * 5 >= r.ttl * 4
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
        // Overheard QM queries are single-use and short-lived (§7.3).
        self.overheard
            .retain(|_, (seen, _, _)| seen.elapsed() < OVERHEARD_WINDOW);
        // Drop TXT expansion state for records that no longer exist.
        let mut live_txt = HashSet::new();
        for svc in &self.services {
            for rec in &svc.records {
                if rec.rtype == 16 {
                    live_txt.insert(Self::txt_key(rec));
                }
            }
        }
        self.expanded_txt.retain(|k| live_txt.contains(k));
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

    /// Number of distinct non-empty `; `-separated pairs in TXT rdata.
    pub fn txt_pair_count(rdata: &str) -> usize {
        let mut seen = HashSet::new();
        rdata
            .split("; ")
            .filter(|pair| !pair.is_empty() && seen.insert(*pair))
            .count()
    }

    /// Whether a record renders with collapsible TXT child rows (multi-pair TXT).
    pub fn is_expandable_txt(rec: &browse::RawRecord) -> bool {
        rec.rtype == 16 && Self::txt_pair_count(&rec.rdata) > 1
    }

    fn txt_key(rec: &browse::RawRecord) -> (String, String, std::net::SocketAddr) {
        (rec.name.clone(), rec.rdata.clone(), rec.source)
    }

    /// Collapsed by default: only records explicitly expanded via `Enter`
    /// show their child rows.
    pub fn is_txt_expanded(&self, rec: &browse::RawRecord) -> bool {
        self.expanded_txt.contains(&Self::txt_key(rec))
    }

    /// Toggle the TXT record under the Tab cursor. Returns false when the
    /// cursor is not on an expandable TXT row (caller falls back to the
    /// service-type fold). Headers select nothing, so `Enter` on a header
    /// keeps folding the service type instead of touching TXT state.
    fn toggle_txt_expanded(&mut self) -> bool {
        if self.selected_service().is_none() {
            return false;
        }
        let key = match self.selected_detail_entry() {
            Some(DetailEntry::Record(rec)) if Self::is_expandable_txt(rec) => Self::txt_key(rec),
            _ => return false,
        };
        if !self.expanded_txt.remove(&key) {
            self.expanded_txt.insert(key);
        }
        // Let the next frame auto-fit the newly shown/hidden children.
        self.detail_free_scroll = false;
        true
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

    /// Entry under the Tab cursor in the Records table: a raw record row or
    /// a question row (table order is raw records first, then questions
    /// by type/newest-first, matching the rendered table).
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
        svc.ordered_questions()
            .into_iter()
            .nth(self.detail_selected - raws.len())
            .map(|q| DetailEntry::Question {
                name: &q.0,
                rtype_str: &q.1,
                raw: &q.4,
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
            qu: false,
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
            query_kas: Vec::new(),
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
        assert!(app.selected_service().is_some());
        let idx = {
            let svc = app.display_service().expect("service displayed");
            svc.ordered_records()
                .iter()
                .position(|r| r.rtype == 16)
                .expect("TXT record merged into service")
        };
        // Park the Tab cursor on the TXT row without going through
        // sync_detail_cursor (which would re-anchor to the old PTR row).
        app.detail_selected = idx;
        app.detail_anchor = app
            .display_service()
            .and_then(|svc| App::identity_at(svc, idx));
    }

    #[test]
    fn txt_children_collapsed_by_default_and_enter_toggles() {
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "a=1; b=2; c=3");
        let rec = app.services[0]
            .ordered_records()
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
            .ordered_records()
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
        app.handle_key(&key(KeyCode::Enter));
        let rec = app.services[0]
            .ordered_records()
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
    fn ctrl_j_pins_viewport_and_tab_resumes_follow() {
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
        assert!(!app.detail_free_scroll);
        app.handle_key(&ctrl(KeyCode::Char('j')));
        assert!(app.detail_free_scroll);
        assert_eq!(app.detail_offset.get(), 1);
        app.handle_key(&ctrl(KeyCode::Char('k')));
        assert_eq!(app.detail_offset.get(), 0);
        // Shift+Tab resumes cursor-following and moves the record cursor
        // up (Tab is parked on the last row, TXT, so it cannot move down).
        let before = app.detail_selected;
        assert!(before > 0);
        app.handle_key(&plain(KeyCode::BackTab));
        assert!(!app.detail_free_scroll);
        assert_eq!(app.detail_selected, before - 1);
    }

    #[test]
    fn expand_clears_manual_scroll() {
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "a=1; b=2");
        app.scroll_detail(5);
        assert!(app.detail_free_scroll);
        assert!(app.toggle_txt_expanded());
        assert!(!app.detail_free_scroll);
    }

    /// Two groups (http, ssh) with one instance each, cursor settled like
    /// the main loop does.
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
        app
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

    #[test]
    fn jk_moves_service_selection() {
        let mut app = two_group_app();
        // Items: [http header, Test, ssh header, Shell]; clamp settles the
        // cursor on the first instance.
        assert_eq!(app.selected_display, 1);
        app.handle_key(&plain_key(KeyCode::Char('j')));
        assert_eq!(app.selected_display, 3);
        app.handle_key(&plain_key(KeyCode::Char('k')));
        assert_eq!(app.selected_display, 1);
    }

    #[test]
    fn hl_jumps_between_groups() {
        let mut app = two_group_app();
        assert_eq!(app.selected_display, 1);
        app.handle_key(&plain_key(KeyCode::Char('l')));
        assert_eq!(app.selected_display, 3);
        app.handle_key(&plain_key(KeyCode::Char('h')));
        assert_eq!(app.selected_display, 1);
        // Shift jumps to the first/last group.
        app.handle_key(&plain_key(KeyCode::Char('L')));
        assert_eq!(app.selected_display, 3);
        app.handle_key(&plain_key(KeyCode::Char('H')));
        assert_eq!(app.selected_display, 1);
    }

    #[test]
    fn arrows_jump_between_groups_like_hl() {
        let mut app = two_group_app();
        assert_eq!(app.selected_display, 1);
        app.handle_key(&plain_key(KeyCode::Right));
        assert_eq!(app.selected_display, 3);
        app.handle_key(&plain_key(KeyCode::Left));
        assert_eq!(app.selected_display, 1);
    }

    #[test]
    fn home_end_and_space_paging() {
        let mut app = two_group_app();
        app.list_viewport.set(2);
        app.handle_key(&plain_key(KeyCode::End));
        assert_eq!(app.selected_display, 3);
        app.handle_key(&plain_key(KeyCode::Home));
        assert_eq!(app.selected_display, 1);
        // Space pages down one viewport (2 stops); b pages back up.
        app.handle_key(&plain_key(KeyCode::Char(' ')));
        assert_eq!(app.selected_display, 3);
        assert!(app.collapsed_types.is_empty());
        app.handle_key(&plain_key(KeyCode::Char('b')));
        assert_eq!(app.selected_display, 1);
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
        assert!(app.detail_free_scroll);
        assert_eq!(app.detail_offset.get(), 1);
        app.handle_key(&plain_key(KeyCode::Char('J')));
        assert_eq!(app.detail_offset.get(), 2);
        app.handle_key(&plain_key(KeyCode::Char('K')));
        assert_eq!(app.detail_offset.get(), 1);
        app.handle_key(&shift(KeyCode::Up));
        assert_eq!(app.detail_offset.get(), 0);
    }

    #[test]
    fn continuous_backoff_is_1s_then_doubling() {
        let mut app = App::new().unwrap();
        app.known_types.insert("_http._tcp.local".to_string());
        let key = ("_http._tcp.local".to_string(), 12);
        app.continuous.insert(
            key.clone(),
            ContinuousQuery {
                next_due: Instant::now() - Duration::from_millis(1),
                interval: Duration::from_secs(1),
                qname: "_http._tcp.local".to_string(),
            },
        );
        app.poll_continuous();
        let entry = app.continuous.get(&key).expect("still scheduled");
        assert_eq!(entry.interval, Duration::from_secs(2));
        // First gap uses the 1s interval, not the doubled 2s.
        assert!(entry.next_due > Instant::now() + Duration::from_millis(500));
        assert!(entry.next_due <= Instant::now() + Duration::from_secs(1));

        // Second gap uses the 2s interval, then doubles to 4s.
        app.continuous.get_mut(&key).unwrap().next_due = Instant::now() - Duration::from_millis(1);
        app.poll_continuous();
        let entry = app.continuous.get(&key).expect("still scheduled");
        assert_eq!(entry.interval, Duration::from_secs(4));
        assert!(entry.next_due > Instant::now() + Duration::from_secs(1));
        assert!(entry.next_due <= Instant::now() + Duration::from_secs(2));
    }

    #[test]
    fn refresh_step_has_no_1s_floor() {
        // TTL 120: classic 6s + 0-2.4s jitter.
        assert_eq!(refresh_step(120, 0), Duration::from_millis(6000));
        assert_eq!(refresh_step(120, 200), Duration::from_millis(8400));
        // TTL 10: 0.5s + 0-0.2s must stay sub-second so the 85/90/95%
        // windows are still reachable; the old 1s floor pushed them
        // past 100%.
        assert_eq!(refresh_step(10, 0), Duration::from_millis(500));
        assert_eq!(refresh_step(10, 200), Duration::from_millis(700));
    }

    #[test]
    fn requery_ignores_expired_rows() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // Age the PTR past 100% TTL: no live row remains for the key.
        for svc in &mut app.services {
            for rec in &mut svc.records {
                if rec.rtype == 12 {
                    rec.received_at = Instant::now() - Duration::from_secs(130);
                }
            }
        }
        app.requery_expiring();
        let key = ("_http._tcp.local".to_string(), 12);
        assert!(
            !app.requeries.contains_key(&key),
            "expired rows must not schedule refresh queries"
        );
    }

    #[test]
    fn requery_postpones_continuous_for_same_key() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // Age PTR into the 80-100% window so a refresh is due.
        for svc in &mut app.services {
            for rec in &mut svc.records {
                if rec.rtype == 12 {
                    rec.received_at = Instant::now() - Duration::from_secs(100);
                }
            }
        }
        // Continuous stream is due right now.
        let ckey = ("_http._tcp.local".to_string(), 12);
        app.continuous.insert(
            ckey.clone(),
            ContinuousQuery {
                next_due: Instant::now() - Duration::from_millis(1),
                interval: Duration::from_secs(2),
                qname: "_http._tcp.local".to_string(),
            },
        );
        app.requery_expiring();
        let entry = app.continuous.get(&ckey).expect("still scheduled");
        // Refresh sent now, so the exponential stream must wait at
        // least its interval instead of firing on the same tick.
        assert!(entry.next_due > Instant::now() + Duration::from_millis(500));
    }

    #[test]
    fn ordered_questions_sort_by_type_then_newest_first() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        let svc = &mut app.services[0];
        let old = Instant::now() - Duration::from_secs(30);
        let new = Instant::now();
        let src: std::net::SocketAddr = "192.168.1.9:5353".parse().unwrap();
        svc.questions = vec![
            ("h.local".to_string(), "SRV".to_string(), src, old, vec![]),
            ("h.local".to_string(), "A".to_string(), src, old, vec![]),
            ("h.local".to_string(), "A".to_string(), src, new, vec![]),
        ];
        let ordered = app.services[0].ordered_questions();
        let got: Vec<(&str, bool)> = ordered
            .iter()
            .map(|q| {
                (
                    q.1.as_str(),
                    q.3.duration_since(old) > Duration::from_secs(1),
                )
            })
            .collect();
        // Type first, then newest first within a type.
        assert_eq!(got, vec![("A", true), ("A", false), ("SRV", false)]);
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
            rtype,
            rtype_str: rtype_str.to_string(),
            flush_bit: false,
            qu,
            ttl: 0,
            rdata: String::new(),
            wire: Vec::new(),
            source,
            iface: String::new(),
            received_at: Instant::now(),
        };
        browse::Event {
            records: Vec::new(),
            questions: vec![q],
            query_kas: kas,
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

    #[test]
    fn duplicate_qm_with_subset_ka_suppresses_continuous() {
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
        // Remote asks the same QM question with a KA subset (empty ⊆ ours).
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
        let entry = app.continuous.get(&ckey).expect("still scheduled");
        // Treated as sent: backed off instead of transmitting.
        assert_eq!(entry.interval, Duration::from_secs(4));
        assert!(entry.next_due > Instant::now() + Duration::from_secs(1));
        // Single-use: entry consumed.
        assert!(!app
            .overheard
            .contains_key(&("_http._tcp.local".to_string(), 12)));
    }

    #[test]
    fn duplicate_qm_with_extra_ka_does_not_suppress() {
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
        // Remote KA holds a target we don't know — must not suppress.
        let ev = query_event(
            "_http._tcp.local.",
            12,
            "PTR",
            false,
            vec![ka_record("_http._tcp.local.", "Other._http._tcp.local.")],
            remote_source(),
        );
        app.ingest_event(&ev);
        app.poll_continuous();
        let entry = app.continuous.get(&ckey).expect("still scheduled");
        assert_eq!(entry.interval, Duration::from_secs(4));
        // Not suppressed: next_due is now+2s from the real send, but the
        // overheard entry remains since it wasn't consumed.
        assert!(app
            .overheard
            .contains_key(&("_http._tcp.local".to_string(), 12)));
    }

    #[test]
    fn qu_and_local_source_never_suppress() {
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
        // QU bit set: not a QM question.
        let ev = query_event(
            "_http._tcp.local.",
            12,
            "PTR",
            true,
            Vec::new(),
            remote_source(),
        );
        app.ingest_event(&ev);
        assert!(app.overheard.is_empty());
        // Loopback from ourselves: ignored even with subset KA.
        let local: std::net::SocketAddr = test_source();
        app.local_ips.insert(local.ip());
        let ev = query_event("_http._tcp.local.", 12, "PTR", false, Vec::new(), local);
        app.ingest_event(&ev);
        assert!(app.overheard.is_empty());
    }
}
