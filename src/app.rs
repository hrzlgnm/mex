use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::Result;
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::layout::Rect;
use simple_dns::TYPE;

use crate::anomalies;
use crate::browse;
use crate::dump;
use crate::ui;

/// Pane with keyboard focus: Tab cycles the service list, the two
/// record tables, the anomalies pane, and the hex dump. Arrows and j/k
/// navigate inside the focused pane; the hex and anomalies panes have no
/// cursor, so their keys scroll.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Focus {
    #[default]
    Services,
    Answers,
    Questions,
    Anomalies,
    Hex,
}

/// Which pane divider is being dragged (or hovered) with the mouse.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DragMode {
    #[default]
    None,
    Vertical,
    HorizUpper,
    HorizMiddle,
    HorizLower,
}

#[derive(Clone, PartialEq, Eq)]
pub enum DisplayItem {
    Host { label: String },
    Instance { index: usize },
    Enum { index: usize },
}

/// Row selected by the j/k cursor in the Records table.
pub enum DetailEntry<'a> {
    Record(&'a browse::RawRecord),
    Question {
        name: &'a str,
        rtype_str: &'a str,
        raw: &'a [u8],
        source: &'a std::net::SocketAddr,
    },
}

/// Identity of one observed question row, shared by the finding lookup
/// and the pane title so the three fields travel as one.
#[derive(Clone, Copy)]
pub struct QuestionKey<'a> {
    pub name: &'a str,
    pub rtype_str: &'a str,
    pub source: &'a std::net::SocketAddr,
}

/// Liveness of a record row for finding purposes. Goodbye rows (TTL 0)
/// and rows past their TTL carry no findings; the table markers and the
/// Anomalies pane only flag live rows.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum RecordLiveness {
    Live,
    Goodbye,
    Expired,
}

/// Liveness of one record row, shared by the finding filter, the pane
/// copy, and the metrics counts so the three cannot disagree about
/// what counts as gone.
pub(crate) fn record_liveness(rec: &browse::RawRecord) -> RecordLiveness {
    if rec.ttl == 0 {
        RecordLiveness::Goodbye
    } else if rec.received_at.elapsed().as_secs() as u32 > rec.ttl {
        RecordLiveness::Expired
    } else {
        RecordLiveness::Live
    }
}

/// What the Anomalies pane shows findings for: the highlighted record
/// or question row, the displayed target while resting on a header, or
/// nothing at all. Single discriminant shared by the finding filter and
/// the pane title, so a new detail kind touches one place.
pub enum AnomalyScope<'a> {
    ServiceLevel(DetailTarget<'a>),
    Record(&'a browse::RawRecord),
    Question(QuestionKey<'a>),
    None,
}

/// One finding in the Anomalies pane plus whether it belongs to the
/// highlighted detail row.
#[derive(Debug)]
pub struct PaneAnomaly {
    pub anomaly: anomalies::Anomaly,
    pub cursor_match: bool,
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
    answers: Vec<browse::RawRecord>,
    subtypes: Vec<Vec<u8>>,
    questions: Vec<QuestionRow>,
    /// Rows evicted by the 10-row cap; surfaced in dumps so a capped
    /// list is never mistaken for a complete packet log.
    pub questions_dropped: u64,
    last_seen: Instant,
}

/// One Questions-pane row: (name, type label, querier, seen at, query
/// packet bytes). `SELF_SOURCE` marks our own inferred sends.
type QuestionRow = (String, String, std::net::SocketAddr, Instant, Vec<u8>);

/// What the latest query activity for an interest was: we transmitted
/// it, §7.3 suppression stood in for it, or a remote querier asked it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QueryOrigin {
    Transmitted,
    Suppressed,
    Observed,
}

impl QueryOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            QueryOrigin::Transmitted => "transmitted",
            QueryOrigin::Suppressed => "suppressed",
            QueryOrigin::Observed => "observed",
        }
    }
}

/// Which schedule owns an interest's next query: the TTL refresh
/// stream, the continuous browse stream, or neither (terminal). Read
/// from the live `requeries`/`continuous` maps, never stored.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum TimerKind {
    Refresh,
    Browse,
    Expired,
}

impl TimerKind {
    pub fn as_str(self) -> &'static str {
        match self {
            TimerKind::Refresh => "refresh",
            TimerKind::Browse => "browse",
            TimerKind::Expired => "expired",
        }
    }
}

/// Lifecycle of an interest's refresh demand: a pending refresh was
/// sent or suppressed, a fresh answer arrived, or the interest went
/// quiet with nothing to show for it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum InterestStatus {
    Transmitted,
    Suppressed,
    Answered,
    Abandoned,
}

impl InterestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            InterestStatus::Transmitted => "transmitted",
            InterestStatus::Suppressed => "suppressed",
            InterestStatus::Answered => "answered",
            InterestStatus::Abandoned => "abandoned",
        }
    }
}

/// Computed per-interest query snapshot for dumps and the TUI: last
/// query event, refresh attempt count, next deadline, owning timer,
/// and lifecycle status. Schedules stay authoritative in
/// `requeries`/`continuous`; nothing here is stored.
struct InterestView {
    state: Option<InterestQueryState>,
    attempt: u8,
    next_due: Option<Instant>,
    timer: TimerKind,
    status: InterestStatus,
}

impl InterestView {
    fn origin(&self) -> Option<QueryOrigin> {
        self.state.as_ref().and_then(|s| s.last().map(|(o, _)| o))
    }

    fn last_at(&self) -> Option<Instant> {
        self.state.as_ref().and_then(|s| s.last().map(|(_, t)| t))
    }

    fn observed(&self) -> Option<&ObservedQuery> {
        self.state.as_ref().and_then(|s| s.observed.as_ref())
    }

    /// Timestamp of the latest event of one origin, if any.
    fn at(&self, origin: QueryOrigin) -> Option<Instant> {
        let s = self.state.as_ref()?;
        match origin {
            QueryOrigin::Transmitted => s.transmitted,
            QueryOrigin::Suppressed => s.suppressed,
            QueryOrigin::Observed => s.observed.as_ref().map(|o| o.at),
        }
    }
}

/// One observed remote question: when, from whom, on which link.
#[derive(Clone, Debug)]
struct ObservedQuery {
    at: Instant,
    from: std::net::SocketAddr,
    iface: String,
}

/// Render-ready per-interest query summary for the Questions pane.
/// ui.rs stays rendering-only: all schedule lookups happen here.
#[derive(Clone, Copy, Debug)]
pub struct InterestSummary {
    pub timer: TimerKind,
    pub next_due_in_secs: Option<u64>,
    /// Whether we ever transmitted or stood down for this interest.
    /// Distinguishes a lapsed local demand ("expired") from a
    /// foreign-only interest we never scheduled (blank DUE).
    pub had_local_demand: bool,
    /// Instant of our last transmitted query for this interest, if any.
    pub last_transmitted_at: Option<Instant>,
    /// Instant of our last §7.3-suppressed query for this interest, if any.
    pub last_suppressed_at: Option<Instant>,
}

impl App {
    /// Per-interest summary for the TUI: latest event age/kind,
    /// owning timer and deadline, plus whether local demand ever
    /// existed. Unknown names yield an empty summary with blank cells.
    pub fn interest_summary(&self, name: &str, rtype: u16) -> InterestSummary {
        let now = Instant::now();
        let view = self.interest_view(&Self::provenance_key(name, rtype));
        InterestSummary {
            timer: view.timer,
            next_due_in_secs: view
                .next_due
                .map(|d| d.saturating_duration_since(now).as_secs()),
            had_local_demand: view
                .state
                .as_ref()
                .is_some_and(|s| s.transmitted.is_some() || s.suppressed.is_some()),
            last_transmitted_at: view.at(QueryOrigin::Transmitted),
            last_suppressed_at: view.at(QueryOrigin::Suppressed),
        }
    }
}
/// Per-interest query provenance: when we last transmitted, last stood
/// down to §7.3 suppression, and last saw a remote querier ask. Keyed
/// like `continuous` by (lowercased name, type) — see
/// `provenance_key`. Schedules stay authoritative in
/// `requeries`/`continuous`; this records what *happened* so dumps and
/// the TUI can tell a sent refresh from suppression and from someone
/// else's question.
#[derive(Clone, Debug, Default)]
struct InterestQueryState {
    transmitted: Option<Instant>,
    transmitted_interfaces: String,
    suppressed: Option<Instant>,
    observed: Option<ObservedQuery>,
}

impl InterestQueryState {
    /// Latest query event and its kind, if any.
    fn last(&self) -> Option<(QueryOrigin, Instant)> {
        [
            (QueryOrigin::Transmitted, self.transmitted),
            (QueryOrigin::Suppressed, self.suppressed),
            (QueryOrigin::Observed, self.observed.as_ref().map(|o| o.at)),
        ]
        .into_iter()
        .filter_map(|(o, t)| t.map(|t| (o, t)))
        .max_by_key(|(_, t)| *t)
    }
}

/// How long provenance survives without a live schedule: matches the
/// service expiry grace so a recently expired interest still reports
/// its terminal state in dumps.
const INTEREST_GRACE: Duration = Duration::from_secs(120);

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
/// Group header for the selectable enumeration row in the Hosts pane.
pub const ENUM_HOST: &str = "(enumeration)";

/// The enumeration name (case-insensitive, trailing dot ignored).
fn is_enum_name(name: &str) -> bool {
    name.trim_end_matches('.')
        .eq_ignore_ascii_case(ENUM_SERVICE)
}

fn same_ptr_target(a: &browse::RawRecord, b: &browse::RawRecord) -> bool {
    match (&a.ptr_target_labels, &b.ptr_target_labels) {
        (Some(a), Some(b)) => {
            a.len() == b.len() && a.iter().zip(b).all(|(a, b)| a.eq_ignore_ascii_case(b))
        }
        (None, None) => a.rdata.eq_ignore_ascii_case(&b.rdata),
        _ => false,
    }
}

fn subtype_owner_parts(rec: &browse::RawRecord) -> Option<(Vec<u8>, String)> {
    let fallback_labels = if rec.owner_labels.is_empty() {
        rec.name
            .trim_end_matches('.')
            .split('.')
            .map(|label| label.as_bytes().to_vec())
            .collect::<Vec<_>>()
    } else {
        Vec::new()
    };
    let labels = if rec.owner_labels.is_empty() {
        fallback_labels.as_slice()
    } else {
        rec.owner_labels.as_slice()
    };
    let [subtype, sub_keyword, service, protocol, local] = labels else {
        return None;
    };
    if !sub_keyword.as_slice().eq_ignore_ascii_case(b"_sub") {
        return None;
    }

    let service_type = [service, protocol, local]
        .iter()
        .map(|label| String::from_utf8_lossy(label).into_owned())
        .collect::<Vec<_>>()
        .join(".");
    Some((subtype.clone(), service_type))
}

fn srv_target(rdata: &str) -> Option<&str> {
    let target = rdata.splitn(4, ' ').nth(3)?.trim().trim_end_matches('.');
    (!target.is_empty()).then_some(target)
}

/// Maximum interval between continuous queries (RFC 6762 §5.2 steady state).
const MAX_CONTINUOUS_INTERVAL: Duration = Duration::from_secs(3600);
/// Local address refresh is unrelated to querying; keep it on its own timer.
const LOCAL_IPS_REFRESH: Duration = Duration::from_secs(10);
const PENDING_ADDR_PRUNE_INTERVAL: Duration = Duration::from_secs(1);

/// Sentinel querier address marking questions inferred from our own send
/// path (multicast loop is disabled, so our transmissions never arrive
/// as events). Port 0 can never be a real mDNS querier.
pub const SELF_SOURCE: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

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
/// Packet arrival times older than this are dropped from the rate window.
const METRICS_WINDOW: Duration = Duration::from_secs(300);

/// Cumulative v2 traffic/query counters for the metrics overlay. Derived
/// snapshot rows come from here plus live state; per-packet maps stay
/// bounded by network size (tens of responders/interfaces).
#[derive(Debug, Default)]
pub struct MetricsCounters {
    pub bytes_total: u64,
    pub packet_times: VecDeque<Instant>,
    pub last_packet_at: Option<Instant>,
    pub records_total: u64,
    pub records_by_type: HashMap<u16, u64>,
    pub questions_total: u64,
    pub qu_questions_seen: u64,
    pub qm_questions_seen: u64,
    pub kas_seen: u64,
    pub goodbyes_seen: u64,
    pub flush_seen: u64,
    pub iface_rx: HashMap<String, u64>,
    pub source_rx: HashMap<std::net::SocketAddr, u64>,
    pub q_sent_continuous: u64,
    pub q_sent_refresh: u64,
    pub qu_sent: u64,
    pub ka_sent: u64,
    pub suppressed_continuous: u64,
    pub suppressed_refresh: u64,
    /// When each §7.3 suppression happened (sliding window for recency).
    pub suppressed_times: VecDeque<Instant>,
    pub services_seen_total: u64,
    pub services_expired_total: u64,
}

fn fmt_age(secs: u64) -> String {
    if secs >= 3600 {
        format!("{}h{:02}m", secs / 3600, secs % 3600 / 60)
    } else if secs >= 60 {
        format!("{}m{:02}s", secs / 60, secs % 60)
    } else {
        format!("{secs}s")
    }
}

fn fmt_bytes(bytes: u64) -> String {
    if bytes >= 1_048_576 {
        format!("{:.1} MiB", bytes as f64 / 1_048_576.0)
    } else if bytes >= 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{bytes} B")
    }
}

pub struct App {
    pub services: Vec<ServiceEntry>,
    pub selected_display: usize,
    pub list_offset: Cell<usize>,
    /// Visible rows of the service list pane (minus borders), recorded
    /// during draw so PageUp/PageDown paging matches the viewport.
    pub list_viewport: Cell<usize>,
    /// Visible rows of the Answers table (minus header/borders), recorded
    /// during draw so paging the record cursor matches the viewport.
    pub record_viewport: Cell<usize>,
    /// Which pane the cursor keys act on. Tab switches panes; arrows and
    /// j/k navigate inside the focused pane.
    pub focus: Focus,
    pub detail_selected: usize,
    pub detail_offset: Cell<usize>,
    /// Manual scroll of the Answers table (`Ctrl-j/k`): while set, the
    /// viewport stays where the user put it instead of following the
    /// `j/k` cursor, so arbitrarily tall TXT expansions can be paged
    /// through. Any cursor or fold action clears it.
    pub detail_free_scroll: bool,
    pub questions_offset: Cell<usize>,
    /// Manual scroll of the Anomalies pane, which follows the record
    /// cursor and has no cursor of its own. Reset when the cursor or
    /// target changes; upper clamping happens at render time.
    pub anomalies_offset: Cell<usize>,
    /// Whether the Anomalies pane tracks the cursor's finding: set on
    /// cursor moves, cleared by any manual scroll. While set, a changed
    /// finding list re-anchors the viewport instead of leaving the
    /// marker behind.
    pub anomalies_follow: Cell<bool>,
    /// Visible rows of the Anomalies pane (minus borders), recorded
    /// during draw so paging matches the viewport.
    pub anomalies_viewport: Cell<usize>,
    /// Manual scroll of the Hex pane, which follows the record cursor and
    /// has no cursor of its own. Reset when the cursor or target changes;
    /// upper clamping happens at render time, where the line count is known.
    pub hex_offset: Cell<usize>,
    /// Visible rows of the Hex pane (minus borders), recorded during draw
    /// so paging matches the viewport.
    pub hex_viewport: Cell<usize>,
    /// Currently selected field in the displayed resource record.
    pub hex_selected_field: Cell<Option<usize>>,
    /// Horizontal split: percent of the body width given to the Hosts pane.
    /// The shared pane borders are the mouse-drag handles.
    pub left_pct: u16,
    /// Vertical split of the right stack: percent of its height given to
    /// Answers, Questions, and Anomalies (the hex pane takes the
    /// remainder). The shared pane borders are mouse-draggable.
    pub answers_pct: u16,
    pub questions_pct: u16,
    pub anomalies_pct: u16,
    /// Active mouse drag; `None` when no button is held on a pane border.
    pub drag: DragMode,
    /// Pane border under the mouse cursor, for highlight. Updated on
    /// `Moved`/`Drag` events; render-only.
    pub hover: Cell<DragMode>,
    /// Last-frame geometry for mouse hit-testing (recorded during draw).
    pub body_rect: Cell<Rect>,
    pub left_rect: Cell<Rect>,
    pub right_rect: Cell<Rect>,
    pub answers_rect: Cell<Rect>,
    pub questions_rect: Cell<Rect>,
    pub anomalies_rect: Cell<Rect>,
    pub hex_rect: Cell<Rect>,
    pub(crate) hex_field_hits: RefCell<Vec<(Rect, usize)>>,
    pub packet_count: u64,
    pub start_time: Instant,
    pub running: bool,
    /// Listen-only mode (`--passive`): never transmit queries.
    pub passive: bool,
    /// Explicit interface selection (`-i/--interfaces`): `None` browses
    /// all usable links; `Some` restricts joins, queries, and ingress to
    /// the named links. Local-address detection stays global.
    pub interfaces: Option<HashSet<String>>,
    /// Metrics overlay popup (`m` toggles, `m`/`Esc` closes).
    pub show_metrics: bool,
    /// Scroll offset inside the metrics popup (viewport recorded at draw).
    pub metrics_scroll: Cell<usize>,
    pub metrics_viewport: Cell<usize>,
    /// Horizontal scroll offset inside the metrics popup, in chars: the
    /// key column stays frozen while long values pan left.
    pub metrics_hscroll: Cell<usize>,
    /// Cumulative v2 counters (traffic, queries, suppressions).
    pub metrics: MetricsCounters,
    /// Cached usable/skipped link snapshot, refreshed on the 10s tick.
    pub link_stats: browse::LinkStats,
    /// Refused-packet accounting from the listener threads (RFC 6762 §11).
    pub drop_stats: Arc<browse::DropStats>,

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
    /// Per-interest query provenance (transmit / suppress / observe),
    /// keyed like `continuous` by (lowercased name, type) — see
    /// `provenance_key`. Pruned with dead interests in `evict_expired`.
    query_history: HashMap<(String, u16), InterestQueryState>,
    /// Enumeration answers learned from `_services._dns-sd._udp.local`
    /// PTR answers: service type -> (original TTL, received_at, ingress
    /// interface). Used as known answers on enumeration requeries
    /// (RFC 6762 §7.1, shared), scoped to the link they came from.
    enum_known: HashMap<String, (u32, Instant, String)>,
    /// Whether the startup QU batch was already sent (RFC 6762 §5.4:
    /// QU only on wake/interface-activation batch, QM afterwards).
    startup_qu_sent: bool,
    last_ip_refresh: Instant,
    collapsed_hosts: HashSet<String>,
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
    detail_enum_key: Option<String>,
    detail_anchor: Option<DetailCursorKey>,
    sticky_key: Option<(String, String)>,
    sticky_enum_key: Option<String>,
    /// Selectable enumeration row. Always present so our own enumeration
    /// demand has a home; answers and questions file here instead of
    /// being skipped as noise.
    pub enum_entries: Vec<EnumEntry>,
    pending_instances: Vec<PendingService>,
    pending_addrs: HashMap<String, Vec<browse::RawRecord>>,
    next_pending_addr_prune: Instant,
    pub raw_events: Vec<browse::Event>,
    /// Transient confirmation popup (e.g. state-dump result), shown for
    /// a few seconds and dismissed by any key.
    status_msg: Option<(String, Instant)>,
}

pub struct ServiceEntry {
    pub instance: String,
    pub service_type: String,
    pub hostname: String,
    pub port: u16,
    pub subtypes: Vec<Vec<u8>>,
    pub answers: Vec<browse::RawRecord>,
    /// Recently seen questions asking for this service:
    /// (name, type, querier, received_at, query packet bytes). Capped.
    pub questions: Vec<QuestionRow>,
    pub questions_dropped: u64,
    pub last_seen: Instant,
    pub is_active: bool,
    /// Most recent packet that touched this service; the right panes fall
    /// back to it once the shared event buffer has moved on.
    pub last_event: Option<browse::Event>,
}

impl ServiceEntry {
    /// Raw answers deduped by name/type/rdata/source (latest wins), sorted by
    /// type then source for display. Same record announced by different
    /// responders counts as distinct observations, grouped adjacently.
    /// Mirrors the replace identity used by `push_record`.
    pub fn ordered_answers(&self) -> Vec<&browse::RawRecord> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for rec in self.answers.iter().rev() {
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

/// One selectable enumeration row: observed answers/questions for
/// `_services._dns-sd._udp.local`.
/// Stored separately from `ServiceEntry` so enumeration never pollutes
/// service counts, expiry, or SRV/TXT/A interests.
pub struct EnumEntry {
    pub name: String,
    pub answers: Vec<browse::RawRecord>,
    pub questions: Vec<QuestionRow>,
    pub questions_dropped: u64,
    pub last_seen: Instant,
    pub last_event: Option<browse::Event>,
}

impl EnumEntry {
    pub fn ordered_answers(&self) -> Vec<&browse::RawRecord> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for rec in self.answers.iter().rev() {
            if seen.insert((
                &rec.name,
                rec.rtype,
                &rec.rdata,
                &rec.ptr_target_labels,
                rec.source,
            )) {
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

    pub fn pane_ident(&self) -> String {
        format!("enumeration: {}", self.name.trim_end_matches('.'))
    }
}

/// Right-pane target: a real service or an enumeration row. The Answers /
/// Questions / Hex panes render through this so both kinds share one
/// cursor, one hex lookup, and one metrics definition.
pub enum DetailTarget<'a> {
    Service(&'a ServiceEntry),
    Enum(&'a EnumEntry),
}

impl<'a> DetailTarget<'a> {
    pub fn ordered_answers(&self) -> Vec<&'a browse::RawRecord> {
        match self {
            DetailTarget::Service(s) => s.ordered_answers(),
            DetailTarget::Enum(e) => e.ordered_answers(),
        }
    }

    pub fn ordered_questions(
        &self,
    ) -> Vec<&'a (String, String, std::net::SocketAddr, Instant, Vec<u8>)> {
        match self {
            DetailTarget::Service(s) => s.ordered_questions(),
            DetailTarget::Enum(e) => e.ordered_questions(),
        }
    }

    pub fn questions_len(&self) -> usize {
        match self {
            DetailTarget::Service(s) => s.questions.len(),
            DetailTarget::Enum(e) => e.questions.len(),
        }
    }

    pub fn all_answers(&self) -> &'a [browse::RawRecord] {
        match self {
            DetailTarget::Service(s) => &s.answers,
            DetailTarget::Enum(e) => &e.answers,
        }
    }

    pub fn last_event(&self) -> Option<&'a browse::Event> {
        match self {
            DetailTarget::Service(s) => s.last_event.as_ref(),
            DetailTarget::Enum(e) => e.last_event.as_ref(),
        }
    }

    pub fn pane_ident(&self) -> String {
        match self {
            DetailTarget::Service(s) => {
                let host = s.hostname.trim_end_matches('.');
                if host.is_empty() {
                    s.instance.clone()
                } else if s.port > 0 {
                    format!("{} @ {}:{}", s.instance, host, s.port)
                } else {
                    format!("{} @ {host}", s.instance)
                }
            }
            DetailTarget::Enum(e) => e.pane_ident(),
        }
    }
}

impl App {
    pub fn new() -> Result<Self> {
        Self::new_with(false, None)
    }

    /// `passive` listens only: no QU batch, no continuous stream, no
    /// TTL refreshes. Everything else (ingest, expiry, display) runs
    /// as usual, so the view shows recently heard traffic decaying by
    /// TTL instead of actively maintained state.
    /// `interfaces` restricts discovery to the named links (`None`
    /// browses all usable links).
    pub fn new_with(passive: bool, interfaces: Option<HashSet<String>>) -> Result<Self> {
        let (query_tx, rx, drop_stats) = browse::spawn(interfaces.clone())?;
        let link_stats = browse::link_stats(interfaces.as_ref());
        log::info!(
            "mex: app created (passive={}, interfaces={:?})",
            passive,
            interfaces
        );
        Ok(Self {
            passive,
            interfaces,
            services: Vec::new(),
            selected_display: 0,
            list_offset: Cell::new(0),
            list_viewport: Cell::new(0),
            record_viewport: Cell::new(0),
            focus: Focus::default(),
            packet_count: 0,
            start_time: Instant::now(),
            running: true,
            rx,
            query_tx,
            continuous: HashMap::new(),
            known_types: HashSet::new(),
            requeries: HashMap::new(),
            query_history: HashMap::new(),
            enum_known: HashMap::new(),
            startup_qu_sent: false,
            last_ip_refresh: Instant::now(),
            collapsed_hosts: HashSet::new(),
            expanded_txt: HashSet::new(),
            local_ips: browse::local_ips(),
            overheard: HashMap::new(),
            detail_selected: 0,
            detail_offset: Cell::new(0),
            detail_free_scroll: false,
            questions_offset: Cell::new(0),
            anomalies_offset: Cell::new(0),
            anomalies_follow: Cell::new(false),
            anomalies_viewport: Cell::new(0),
            hex_offset: Cell::new(0),
            hex_viewport: Cell::new(0),
            hex_selected_field: Cell::new(None),
            left_pct: 33,
            answers_pct: 30,
            questions_pct: 25,
            anomalies_pct: 20,
            drag: DragMode::None,
            hover: Cell::new(DragMode::None),
            body_rect: Cell::new(Rect::default()),
            left_rect: Cell::new(Rect::default()),
            right_rect: Cell::new(Rect::default()),
            answers_rect: Cell::new(Rect::default()),
            questions_rect: Cell::new(Rect::default()),
            anomalies_rect: Cell::new(Rect::default()),
            hex_rect: Cell::new(Rect::default()),
            hex_field_hits: RefCell::new(Vec::new()),
            detail_svc_key: None,
            detail_enum_key: None,
            detail_anchor: None,
            sticky_key: None,
            sticky_enum_key: None,
            enum_entries: vec![EnumEntry {
                name: ENUM_SERVICE.to_string(),
                answers: Vec::new(),
                questions: Vec::new(),
                questions_dropped: 0,
                last_seen: Instant::now(),
                last_event: None,
            }],
            pending_instances: Vec::new(),
            pending_addrs: HashMap::new(),
            next_pending_addr_prune: Instant::now(),
            raw_events: Vec::new(),
            status_msg: None,
            show_metrics: false,
            metrics_scroll: Cell::new(0),
            metrics_viewport: Cell::new(0),
            metrics_hscroll: Cell::new(0),
            metrics: MetricsCounters::default(),
            link_stats,
            drop_stats,
        })
    }

    pub fn run(&mut self, terminal: &mut Option<ui::Terminal>) -> Result<()> {
        log::info!("mex: run started (tui={})", terminal.is_some());
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

            // Surface retained log write failures (terminal-safe: the
            // popup, not stderr, so the TUI is not corrupted).
            if let Some(msg) = crate::take_log_error() {
                self.status_msg = Some((msg, Instant::now()));
            }

            if event::poll(Duration::from_millis(80))? {
                // Drain everything pending so mouse drags stay smooth at
                // 12fps instead of handling one event per frame.
                loop {
                    match event::read()? {
                        Event::Key(key) => {
                            if key.kind == KeyEventKind::Press {
                                // Unix suspend precedes all key handling (even
                                // the metrics overlay): raw mode delivers
                                // Ctrl+Z as a key event, not SIGTSTP.
                                #[cfg(unix)]
                                if Self::is_suspend_key(&key) {
                                    if !ui::suspend(terminal)? {
                                        self.running = false;
                                        return Ok(());
                                    }
                                    // Break out to redraw immediately: the
                                    // inner loop would block on `read()` until
                                    // the next input event, leaving the
                                    // freshly cleared screen blank.
                                    break;
                                }
                                self.handle_key(&key);
                            }
                        }
                        Event::Mouse(mouse) => self.handle_mouse(&mouse),
                        Event::Resize(_, _) => {}
                        _ => {}
                    }
                    if !event::poll(Duration::ZERO)? {
                        break;
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
            // Surface retained log write failures (stderr is safe here:
            // no TUI to corrupt).
            if let Some(msg) = crate::take_log_error() {
                eprintln!("mex: {msg}");
            }
            // Short tick like the TUI loop so the RFC 6762 §5.2 20-120ms
            // first-query delay is not quantized to a full second.
            std::thread::sleep(Duration::from_millis(50));
        }
        Ok(())
    }

    fn flush_pending_addrs(&mut self) {
        let mut services_by_host: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, svc) in self.services.iter().enumerate() {
            let mut hosts = HashSet::new();
            let selected = svc.hostname.trim_end_matches('.').to_lowercase();
            if !selected.is_empty() {
                hosts.insert(selected);
            }
            for rec in &svc.answers {
                if rec.rtype != 33 || rec.ttl <= rec.received_at.elapsed().as_secs() as u32 {
                    continue;
                }
                if let Some(target) = srv_target(&rec.rdata) {
                    hosts.insert(target.to_lowercase());
                }
            }
            for host in hosts {
                services_by_host.entry(host).or_default().push(i);
            }
        }

        for (host, services) in services_by_host {
            if let Some(records) = self.pending_addrs.remove(&host) {
                for rec in records {
                    for &i in &services {
                        self.push_record(i, &rec);
                    }
                }
            }
        }
    }

    fn pending_addrs_count(&self) -> usize {
        self.pending_addrs.values().map(Vec::len).sum()
    }

    fn drain_events(&mut self) {
        let mut batch: Vec<browse::Event> = Vec::new();
        while let Ok(ev) = self.rx.try_recv() {
            self.packet_count += 1;
            batch.push(ev);
        }
        let target_changed = batch
            .iter()
            .any(|ev| ev.answers.iter().any(|rec| rec.rtype == 33 && rec.ttl > 0));
        for ev in &batch {
            self.note_packet_metrics(ev);
            self.raw_events.push(ev.clone());
        }
        if self.raw_events.len() > 2000 {
            self.raw_events
                .drain(0..self.raw_events.len().saturating_sub(2000));
        }
        // Prune the sliding rate windows even on idle ticks.
        while self
            .metrics
            .packet_times
            .front()
            .is_some_and(|t| t.elapsed() > METRICS_WINDOW)
        {
            self.metrics.packet_times.pop_front();
        }
        while self
            .metrics
            .suppressed_times
            .front()
            .is_some_and(|t| t.elapsed() > METRICS_WINDOW)
        {
            self.metrics.suppressed_times.pop_front();
        }

        if !batch.is_empty() {
            log::trace!("mex: drained {} packet(s)", batch.len());
        }
        for ev in &batch {
            self.ingest_event(ev);
        }

        if target_changed {
            self.flush_pending_addrs();
        }
    }

    /// Cumulative per-packet accounting for the metrics overlay.
    fn note_packet_metrics(&mut self, ev: &browse::Event) {
        let now = Instant::now();
        let m = &mut self.metrics;
        m.bytes_total += ev.raw_bytes.len() as u64;
        m.packet_times.push_back(now);
        m.last_packet_at = Some(now);
        m.records_total += ev.answers.len() as u64;
        for rec in &ev.answers {
            *m.records_by_type.entry(rec.rtype).or_insert(0) += 1;
            if rec.flush_bit {
                m.flush_seen += 1;
            }
            if rec.ttl == 0 {
                m.goodbyes_seen += 1;
            }
        }
        m.questions_total += ev.questions.len() as u64;
        for q in &ev.questions {
            if q.qu {
                m.qu_questions_seen += 1;
            } else {
                m.qm_questions_seen += 1;
            }
        }
        m.kas_seen += ev.query_kas.len() as u64;
        // Ingress link of the packet: first record/question/KA. A name
        // that never resolved falls back to the kernel index (`if#7`)
        // so unmapped traffic stays identifiable instead of piling up
        // under one opaque bucket.
        let (iface, ifindex) = ev
            .answers
            .first()
            .or(ev.questions.first())
            .or(ev.query_kas.first())
            .map(|r| (r.iface.as_str(), r.ifindex))
            .unwrap_or(("", 0));
        *m.iface_rx
            .entry(Self::link_key(iface, ifindex))
            .or_insert(0) += 1;
        *m.source_rx.entry(ev.source).or_insert(0) += 1;
    }

    /// Display key for an ingress link: the interface name, or the
    /// kernel index when the name never resolved.
    fn link_key(iface: &str, ifindex: u32) -> String {
        if iface.is_empty() {
            format!("if#{ifindex}")
        } else {
            iface.to_string()
        }
    }

    fn remaining_ttl(rec: &browse::RawRecord) -> u32 {
        rec.ttl
            .saturating_sub(rec.received_at.elapsed().as_secs() as u32)
    }

    /// Known PTR answers for a service type (or enumeration), RFC 6762 §7.1:
    /// only answers with at least half of the original TTL remaining, sent
    /// with their remaining TTL so responders can suppress duplicates.
    /// Unique types (SRV/TXT/A/AAAA) are intentionally omitted: §7.1 notes
    /// known-answer suppression is for shared answers. Each answer carries
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
            if !s.service_type.eq_ignore_ascii_case(owner) {
                continue;
            }
            for rec in &s.answers {
                push_rec(rec, &mut out);
            }
        }
        for p in &self.pending_instances {
            if !p.service_type.eq_ignore_ascii_case(owner) {
                continue;
            }
            for rec in &p.answers {
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

    fn requery_expiring(&mut self) {
        let now = Instant::now();
        // Per-key minimum TTL plus whether any *live* row reached the 80%
        // window. Expired rows (elapsed > TTL) are not refreshed: RFC 6762
        // §5.2 deletes the record at 100% after four unanswered queries.
        let mut ttl_by_key: HashMap<(String, u16), u32> = HashMap::new();
        let mut triggered: HashSet<(String, u16)> = HashSet::new();
        let mut live_keys: HashSet<(String, u16)> = HashSet::new();
        let scan = |rec: &browse::RawRecord,
                    ttl_by_key: &mut HashMap<(String, u16), u32>,
                    triggered: &mut HashSet<(String, u16)>,
                    live_keys: &mut HashSet<(String, u16)>| {
            if rec.ttl == 0 {
                return;
            }
            match rec.rtype {
                12 | 33 | 16 | 1 | 28 => {}
                _ => return,
            }
            let key = (rec.name.trim_end_matches('.').to_string(), rec.rtype);
            let elapsed = rec.received_at.elapsed().as_secs() as u32;
            if elapsed > rec.ttl {
                return;
            }
            live_keys.insert(key.clone());
            ttl_by_key
                .entry(key.clone())
                .and_modify(|t| *t = (*t).min(rec.ttl))
                .or_insert(rec.ttl);
            if elapsed * 5 >= rec.ttl * 4 {
                triggered.insert(key);
            }
        };
        for svc in &self.services {
            for rec in &svc.answers {
                scan(rec, &mut ttl_by_key, &mut triggered, &mut live_keys);
            }
        }
        for entry in &self.enum_entries {
            for rec in &entry.answers {
                scan(rec, &mut ttl_by_key, &mut triggered, &mut live_keys);
            }
        }
        // Drop refresh schedules whose rows all expired: no maintenance
        // without a live record (RFC 6762 §5.2 deletes at 100%).
        self.requeries.retain(|k, _| live_keys.contains(k));
        if triggered.is_empty() {
            return;
        }
        log::debug!(
            "mex: cache refresh triggered for {} interest(s)",
            triggered.len()
        );
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
            let Some(rt) = browse::record_type_from_u16(key.1) else {
                continue;
            };
            let ka = if rt == TYPE::PTR {
                if is_enum_name(&key.0) {
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
                log::debug!("mex: suppressed refresh query for {} (overheard)", key.0);
                self.metrics.suppressed_refresh += 1;
                self.metrics.suppressed_times.push_back(now);
                self.note_query(&key.0, key.1, QueryOrigin::Suppressed, now);
                self.route_own_question(&key.0, key.1, false);
                self.postpone_continuous_for_refresh(&key, now);
                let unanswered = (count + 1).min(4);
                if unanswered >= 4 {
                    self.requeries.remove(&key);
                } else {
                    self.requeries.insert(key, (now + step, unanswered));
                }
                continue;
            }
            self.metrics.q_sent_refresh += 1;
            self.metrics.ka_sent += ka.len() as u64;
            if self.query_tx.send(browse::QueryRequest {
                name: key.0.clone(),
                record_type: rt,
                known_answers: ka,
                qu: false,
            }) {
                self.note_query(&key.0, key.1, QueryOrigin::Transmitted, now);
            } else {
                log::warn!(
                    "mex: dropped refresh query for {} (listener channels closed)",
                    key.0
                );
            }
            self.route_own_question(&key.0, key.1, false);
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

    /// Map key for `continuous` and `requeries`: lowercased name per
    /// RFC 6763 §7 / RFC 1035 §2.3.1 (service types and subtypes compare
    /// case-insensitively; host names too). The query itself keeps wire
    /// case via `qname` / the desired-map value.
    fn continuous_key(name: &str, rtype: u16) -> (String, u16) {
        (name.to_lowercase(), rtype)
    }

    /// Provenance map key: dot-trimmed lowercased name plus type, so
    /// wire case and trailing dots collapse the way the scheduler keys
    /// do (RFC 6763 §7).
    fn provenance_key(name: &str, rtype: u16) -> (String, u16) {
        (name.trim_end_matches('.').to_lowercase(), rtype)
    }

    /// Record a query event for an interest: we transmitted it or §7.3
    /// suppression stood in for it, stamped at action time.
    fn note_query(&mut self, name: &str, rtype: u16, origin: QueryOrigin, at: Instant) {
        let mut query_interfaces: Vec<String> = self
            .link_stats
            .v4
            .iter()
            .map(|(name, _)| name.clone())
            .chain(self.link_stats.v6.iter().map(|(name, _)| name.clone()))
            .filter(|name| {
                self.interfaces
                    .as_ref()
                    .is_none_or(|selected| selected.contains(name))
            })
            .collect();
        query_interfaces.sort();
        query_interfaces.dedup();
        let query_interfaces = query_interfaces.join(", ");
        let entry = self
            .query_history
            .entry(Self::provenance_key(name, rtype))
            .or_default();
        match origin {
            QueryOrigin::Transmitted => {
                entry.transmitted = Some(at);
                entry.transmitted_interfaces = query_interfaces;
            }
            QueryOrigin::Suppressed => entry.suppressed = Some(at),
            QueryOrigin::Observed => {
                // Observed questions carry their own packet timestamp
                // and source; use `note_observed` instead.
            }
        }
    }

    /// Record an observed remote question with its packet timestamp,
    /// querier, and ingress interface, so dumps can identify which link
    /// and browser asked (RFC 6762 §5.4/§11 context).
    fn note_observed(&mut self, q: &browse::RawRecord, ev: &browse::Event) {
        let entry = self
            .query_history
            .entry(Self::provenance_key(&q.name, q.rtype))
            .or_default();
        entry.observed = Some(ObservedQuery {
            at: q.received_at,
            from: ev.source,
            iface: q.iface.clone(),
        });
    }

    /// Whether a live (unexpired, nonzero-TTL) answer row exists for a
    /// normalized interest key, across services, enumeration, and
    /// pending instances.
    fn has_live_answer(&self, key: &(String, u16)) -> bool {
        let live_row = |rec: &browse::RawRecord| {
            // Canonical key comparison (not ASCII-only): `É` and `é`
            // must hit the same interest.
            Self::provenance_key(&rec.name, rec.rtype).0 == key.0
                && rec.ttl > 0
                && Self::remaining_ttl(rec) > 0
        };
        self.services
            .iter()
            .any(|s| s.answers.iter().any(&live_row))
            || self
                .enum_entries
                .iter()
                .any(|e| e.answers.iter().any(&live_row))
            || self
                .pending_instances
                .iter()
                .any(|p| p.answers.iter().any(&live_row))
            || self.pending_addrs.values().flatten().any(live_row)
    }

    /// Earliest point at which the refresh scan will trigger for an
    /// interest: 80% of TTL past each live row's receipt, minimum
    /// across rows. Matches the scan's coverage exactly (services +
    /// enumeration answers, browsable types only) so the projection
    /// never predicts a refresh the scheduler would not send. `None`
    /// in passive mode: a passive browser transmits nothing, so no
    /// refresh is ever due.
    fn next_refresh_due(&self, key: &(String, u16)) -> Option<Instant> {
        if self.passive {
            return None;
        }
        let deadline = |rec: &browse::RawRecord| {
            if rec.ttl == 0 {
                return None;
            }
            match rec.rtype {
                12 | 33 | 16 | 1 | 28 => {}
                _ => return None,
            }
            if rec.rtype != key.1
                || Self::provenance_key(&rec.name, rec.rtype).0 != key.0
                || rec.received_at.elapsed().as_secs() as u32 > rec.ttl
            {
                return None;
            }
            // Earliest whole second satisfying the scan's trigger.
            Some(rec.received_at + Duration::from_secs((rec.ttl as u64 * 4).div_ceil(5)))
        };
        let earliest = self
            .services
            .iter()
            .flat_map(|s| s.answers.iter())
            .chain(self.enum_entries.iter().flat_map(|e| e.answers.iter()))
            .filter_map(deadline)
            .min()?;
        // A row already past 80% with no entry yet fires on the next
        // tick: clamp to now instead of showing a stale past deadline.
        Some(earliest.max(Instant::now()))
    }

    /// Authoritative per-interest snapshot for dumps and the TUI.
    /// Refresh state wins over the continuous stream (urgent TTL
    /// maintenance outranks hourly rediscovery); with no schedule the
    /// interest is terminal. Status distinguishes a pending send from
    /// suppression, and a quiet interest with live answers (answered)
    /// from one with nothing left (abandoned).
    fn interest_view(&self, key: &(String, u16)) -> InterestView {
        // Canonicalize once: map keys keep wire case or are lowercased
        // depending on the map, and eq_ignore_ascii_case only folds
        // a-z, so compare through `provenance_key` everywhere (`É`
        // and `é` must hit the same interest).
        let key = Self::provenance_key(&key.0, key.1);
        let state = self.query_history.get(&key).cloned();
        let (attempt, refresh_due) = self
            .requeries
            .iter()
            .find(|(k, _)| Self::provenance_key(&k.0, k.1) == key)
            .map(|(_, (due, count))| (*count, Some(*due)))
            .unwrap_or((0, None));
        let browse_due = self
            .continuous
            .iter()
            .find(|(k, _)| Self::provenance_key(&k.0, k.1) == key)
            .map(|(_, e)| e.next_due);
        let (timer, next_due) = match (refresh_due, browse_due) {
            (Some(due), _) => (TimerKind::Refresh, Some(due)),
            (None, Some(due)) => match self.next_refresh_due(&key) {
                // Projected refresh beats the browse stream: the
                // earlier maintenance owns DUE.
                Some(proj) if proj < due => (TimerKind::Refresh, Some(proj)),
                _ => (TimerKind::Browse, Some(due)),
            },
            // No schedule at all, but live rows would still trigger one:
            // the scheduler fires regardless of continuous membership
            // (except passive mode, which never transmits).
            (None, None) => match self.next_refresh_due(&key) {
                Some(proj) => (TimerKind::Refresh, Some(proj)),
                None => (TimerKind::Expired, None),
            },
        };
        let last_own = state.as_ref().and_then(|s| {
            [
                (QueryOrigin::Transmitted, s.transmitted),
                (QueryOrigin::Suppressed, s.suppressed),
            ]
            .into_iter()
            .filter_map(|(o, t)| t.map(|t| (o, t)))
            .max_by_key(|(_, t)| *t)
            .map(|(o, _)| o)
        });
        // Requery entries are only inserted alongside a send or a
        // suppression decision (never speculatively), so a pending
        // refresh always has a last own action; the Transmitted arm
        // below is the defensive fallback, not a reachable default.
        let status = match (refresh_due.is_some(), last_own) {
            (true, Some(QueryOrigin::Suppressed)) => InterestStatus::Suppressed,
            (true, _) => InterestStatus::Transmitted,
            (false, _) if self.has_live_answer(&key) => InterestStatus::Answered,
            (false, _) => InterestStatus::Abandoned,
        };
        InterestView {
            state,
            attempt,
            next_due,
            timer,
            status,
        }
    }

    /// Strip a dot-separated suffix case-insensitively, returning the
    /// wire-case prefix without the separating dot. The split offset must
    /// be a character boundary: instance names may hold multi-byte UTF-8
    /// (RFC 6763 §4.1.1), so byte-slicing inside a character would panic.
    fn strip_suffix_ci<'a>(full: &'a str, suffix: &str) -> Option<&'a str> {
        if full.len() <= suffix.len() {
            return None;
        }
        let off = full.len() - suffix.len();
        if !full.is_char_boundary(off) {
            return None;
        }
        let (prefix, tail) = full.split_at(off);
        if !tail.eq_ignore_ascii_case(suffix) {
            return None;
        }
        prefix.strip_suffix('.')
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
            let Some(rt) = browse::record_type_from_u16(key.1) else {
                continue;
            };
            let ka = if rt == TYPE::PTR {
                if is_enum_name(&key.0) {
                    self.known_enum_answers()
                } else {
                    self.known_ptrs(&key.0)
                }
            } else {
                Vec::new()
            };
            // QU on the first transmission of the enumeration query
            // (RFC 6762 §5.4 startup batch); everything afterwards is QM.
            // First-transmission (interval still 1s) rather than a single
            // flag so the QU survives the 20-120ms first-query delay.
            let qu = key.1 == 12
                && is_enum_name(&key.0)
                && self
                    .continuous
                    .get(&key)
                    .is_some_and(|e| e.interval == Duration::from_secs(1));
            // RFC 6762 §7.3: another querier just asked the same QM
            // question with no KA we wouldn't send — treat ours as sent.
            // QU elicits unicast and is never suppressed.
            if !qu && self.suppressed_by_overheard(&key, &ka) {
                log::debug!("mex: suppressed continuous query for {} (overheard)", key.0);
                let now = Instant::now();
                self.metrics.suppressed_continuous += 1;
                self.metrics.suppressed_times.push_back(now);
                self.note_query(&key.0, key.1, QueryOrigin::Suppressed, now);
                self.route_own_question(&key.0, key.1, false);
                self.advance_continuous(&key, now);
                continue;
            }
            if qu {
                self.startup_qu_sent = true;
                // Keep the flag for the passive-mode test; per-name QU above
                // no longer depends on it.
            }
            self.metrics.q_sent_continuous += 1;
            log::debug!(
                "mex: sending continuous query for {} (qu={})",
                send_name,
                qu
            );
            if qu {
                self.metrics.qu_sent += 1;
            }
            self.metrics.ka_sent += ka.len() as u64;
            if self.query_tx.send(browse::QueryRequest {
                name: send_name.clone(),
                record_type: rt,
                known_answers: ka,
                qu,
            }) {
                self.note_query(&send_name, key.1, QueryOrigin::Transmitted, now);
            } else {
                log::warn!(
                    "mex: dropped continuous query for {} (listener channels closed)",
                    send_name
                );
            }
            self.route_own_question(&send_name, key.1, qu);
            // RFC 6762 §5.2: at least 1s between the first two, then at
            // least doubling, capped at one query per hour. Send using the
            // current interval, then double for the following gap, so the
            // stream is 1s, 2s, 4s, ... (doubling before use would skip
            // the 1s gap and start at 2s).
            self.advance_continuous(&key, now);
        }
    }

    fn send_queries(&mut self) {
        // Passive mode transmits nothing: no QU batch, no continuous
        // stream, no TTL refreshes. Filing received data and the link
        // refresh below still run.
        if !self.passive {
            // Learn service types before scheduling so new PTR owners are
            // browsed without waiting for a record-bearing service entry.
            // Lowercased: `_HTTP` and `_http` are the same type (RFC 6763 §7).
            for svc in &self.services {
                self.known_types.insert(svc.service_type.to_lowercase());
            }
            for p in &self.pending_instances {
                self.known_types.insert(p.service_type.to_lowercase());
            }
            for t in self.enum_known.keys() {
                self.known_types.insert(t.clone());
            }

            self.requery_expiring();
            self.poll_continuous();
        }

        // Refresh in case interfaces/addresses changed (cheap: ~1 fork/min).
        // Independent of query backoff.
        if self.last_ip_refresh.elapsed() >= LOCAL_IPS_REFRESH {
            self.last_ip_refresh = Instant::now();
            self.local_ips = browse::local_ips();
            self.link_stats = browse::link_stats(self.interfaces.as_ref());
        }
    }

    pub fn display_items(&self) -> Vec<DisplayItem> {
        struct G {
            label: String,
            indices: Vec<usize>,
        }

        let mut groups: Vec<G> = Vec::new();
        for (i, s) in self.services.iter().enumerate() {
            let key = Self::host_key(&s.hostname);
            match groups.iter_mut().find(|g| g.label == key) {
                Some(g) => g.indices.push(i),
                None => groups.push(G {
                    label: key,
                    indices: vec![i],
                }),
            }
        }

        let mut items = Vec::new();
        // Enumeration group first: global browse state, always present so
        // our own enumeration demand has a home even before any answer.
        items.push(DisplayItem::Host {
            label: ENUM_HOST.to_string(),
        });
        if !self.collapsed_hosts.contains(ENUM_HOST) {
            for (idx, entry) in self.enum_entries.iter().enumerate() {
                let _ = entry;
                items.push(DisplayItem::Enum { index: idx });
            }
        }
        groups.sort_by(|a, b| {
            // Unknown hosts (empty key) sort last.
            match (a.label.is_empty(), b.label.is_empty()) {
                (true, false) => std::cmp::Ordering::Greater,
                (false, true) => std::cmp::Ordering::Less,
                _ => a.label.cmp(&b.label),
            }
        });
        for g in &groups {
            let mut sorted = g.indices.clone();
            sorted.sort_by(|&a, &b| self.services[a].instance.cmp(&self.services[b].instance));
            items.push(DisplayItem::Host {
                label: g.label.clone(),
            });
            if self.collapsed_hosts.contains(&g.label) {
                continue;
            }
            for idx in sorted {
                items.push(DisplayItem::Instance { index: idx });
            }
        }
        items
    }

    /// Normalized group key for host grouping: lowercased hostname without
    /// trailing dot, `""` when the service has no hostname yet.
    fn host_key(hostname: &str) -> String {
        hostname.trim_end_matches('.').to_lowercase()
    }

    /// Display name for a host group key: first-seen hostname without its
    /// trailing dot or redundant `.local` suffix, or `(unknown host)` when
    /// no hostname is known yet. Grouping keys keep the full name; this
    /// is display-only.
    pub fn host_display_name(&self, key: &str) -> String {
        if key.is_empty() {
            return "(unknown host)".to_string();
        }
        if key == ENUM_HOST {
            return ENUM_HOST.to_string();
        }
        for s in &self.services {
            if Self::host_key(&s.hostname) == key {
                let trimmed = s.hostname.trim_end_matches('.');
                if !trimmed.is_empty() {
                    return Self::short_hostname(trimmed);
                }
            }
        }
        Self::short_hostname(key)
    }

    /// Short display form of a hostname: the redundant `.local` suffix
    /// removed (`printer.local.` → `printer`). Case-insensitive; names
    /// that merely contain `local` elsewhere are untouched.
    fn short_hostname(name: &str) -> String {
        let trimmed = name.trim_end_matches('.');
        if trimmed.len() > ".local".len() {
            let off = trimmed.len() - ".local".len();
            if trimmed.is_char_boundary(off) && trimmed[off..].eq_ignore_ascii_case(".local") {
                return trimmed[..off].to_string();
            }
        }
        trimmed.to_string()
    }

    /// Live addresses (A/AAAA rdata) aggregated across all services on the
    /// host, deduped with IPv4 first. Expired rows are omitted.
    pub fn host_addresses(&self, key: &str) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        for s in &self.services {
            if Self::host_key(&s.hostname) != key {
                continue;
            }
            // Collect the live SRV targets for this service so addresses
            // published under an alternate (non-selected) target are still
            // surfaced on the selected host.
            let mut targets = vec![key.to_string()];
            for r in &s.answers {
                if r.rtype != 33 {
                    continue;
                }
                if r.ttl <= r.received_at.elapsed().as_secs() as u32 {
                    continue;
                }
                let t = r
                    .rdata
                    .splitn(4, ' ')
                    .nth(3)
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('.')
                    .to_lowercase();
                if !t.is_empty() && !targets.contains(&t) {
                    targets.push(t);
                }
            }
            for rec in &s.answers {
                if rec.rtype != 1 && rec.rtype != 28 {
                    continue;
                }
                if rec.ttl <= rec.received_at.elapsed().as_secs() as u32 {
                    continue;
                }
                let owner = rec.name.trim_end_matches('.').to_lowercase();
                if !targets.contains(&owner) {
                    continue;
                }
                let ip = rec.rdata.trim().to_string();
                if ip.is_empty() || !seen.insert(ip.clone()) {
                    continue;
                }
                if let Ok(addr) = ip.parse::<std::net::IpAddr>() {
                    if addr.is_ipv4() {
                        v4.push(ip);
                    } else {
                        v6.push(ip);
                    }
                } else if rec.rtype == 1 {
                    v4.push(ip);
                } else {
                    v6.push(ip);
                }
            }
        }
        v4.sort();
        v6.sort();
        v4.extend(v6);
        v4
    }

    pub fn host_service_count(&self, key: &str) -> usize {
        if key == ENUM_HOST {
            return self.enum_entries.len();
        }
        self.services
            .iter()
            .filter(|s| Self::host_key(&s.hostname) == key)
            .count()
    }

    /// Nerd Font level icon for an anomaly severity, shown in place of the
    /// severity word in metrics keys. FontAwesome subset (single cell in
    /// every Nerd Font): U+F057 times-circle (error), U+F071 warning
    /// (warning), U+F05A info-circle (info).
    pub(crate) fn anomaly_level_icon(severity: anomalies::Severity) -> char {
        match severity {
            anomalies::Severity::Error => '\u{f057}',
            anomalies::Severity::Warning => '\u{f071}',
            anomalies::Severity::Info => '\u{f05a}',
        }
    }

    /// Rows for the metrics overlay: `(key, value)` with an empty value
    /// marking a section header. Pure snapshot of cumulative counters plus
    /// live state; cheap enough to rebuild every frame.
    pub fn metrics_rows(&self) -> Vec<(String, String)> {
        let mut rows: Vec<(String, String)> = Vec::new();
        let section = |rows: &mut Vec<(String, String)>, name: &str| {
            rows.push((name.to_string(), String::new()));
        };
        let kv = |rows: &mut Vec<(String, String)>, k: &str, v: String| {
            rows.push((k.to_string(), v));
        };

        // Session / traffic.
        section(&mut rows, "Session");
        let uptime_secs = self.start_time.elapsed().as_secs();
        kv(&mut rows, "uptime", fmt_age(uptime_secs));
        kv(&mut rows, "packets", self.packet_count.to_string());
        let per_min = if uptime_secs > 0 {
            self.packet_count as f64 * 60.0 / uptime_secs as f64
        } else {
            0.0
        };
        kv(&mut rows, "pkt/min overall", format!("{per_min:.1}"));
        let last_60 = self
            .metrics
            .packet_times
            .iter()
            .filter(|t| t.elapsed() <= Duration::from_secs(60))
            .count();
        kv(&mut rows, "pkt/min last 60s", last_60.to_string());
        let avg = self
            .metrics
            .bytes_total
            .checked_div(self.packet_count)
            .unwrap_or(0);
        kv(
            &mut rows,
            "bytes",
            format!("{} (avg {avg} B/pkt)", fmt_bytes(self.metrics.bytes_total)),
        );
        kv(
            &mut rows,
            "last packet",
            self.metrics
                .last_packet_at
                .map(|t| format!("{} ago", fmt_age(t.elapsed().as_secs())))
                .unwrap_or_else(|| "—".to_string()),
        );

        // Discovery.
        section(&mut rows, "Discovery");
        let active = self.services.iter().filter(|s| s.is_active).count();
        kv(
            &mut rows,
            "services",
            format!(
                "{} ({} active, {} inactive)",
                self.services.len(),
                active,
                self.services.len().saturating_sub(active)
            ),
        );
        kv(
            &mut rows,
            "services ever / expired",
            format!(
                "{} / {}",
                self.metrics.services_seen_total, self.metrics.services_expired_total
            ),
        );
        kv(
            &mut rows,
            "hosts",
            // The `(enumeration)` group is navigation, not a host.
            self.group_labels()
                .iter()
                .filter(|l| *l != ENUM_HOST)
                .count()
                .to_string(),
        );
        kv(
            &mut rows,
            "types / enum",
            format!("{} / {}", self.known_types.len(), self.enum_known.len()),
        );
        for entry in &self.enum_entries {
            let live_answers = entry
                .answers
                .iter()
                .filter(|r| r.ttl > 0 && r.received_at.elapsed().as_secs() as u32 <= r.ttl)
                .count();
            let mut eq = HashSet::new();
            for q in &entry.questions {
                if q.2 != SELF_SOURCE {
                    eq.insert(q.2);
                }
            }
            kv(
                &mut rows,
                &format!("enum {}", entry.name.trim_end_matches('.')),
                format!(
                    "{} Q current ({} queriers) · {} answers ({} live)",
                    entry.questions.len(),
                    eq.len(),
                    entry.answers.len(),
                    live_answers,
                ),
            );
        }
        kv(
            &mut rows,
            "pending inst / addrs",
            format!(
                "{} / {}",
                self.pending_instances.len(),
                self.pending_addrs_count()
            ),
        );
        let (live, expired, goodbye) = self.current_record_liveness();
        kv(
            &mut rows,
            "answers current",
            format!("{live} live, {expired} expired, {goodbye} goodbye"),
        );
        kv(
            &mut rows,
            "answers ever",
            format!(
                "{} (PTR {} · SRV {} · TXT {} · A {} · AAAA {} · other {})",
                self.metrics.records_total,
                self.metrics.records_by_type.get(&12).copied().unwrap_or(0),
                self.metrics.records_by_type.get(&33).copied().unwrap_or(0),
                self.metrics.records_by_type.get(&16).copied().unwrap_or(0),
                self.metrics.records_by_type.get(&1).copied().unwrap_or(0),
                self.metrics.records_by_type.get(&28).copied().unwrap_or(0),
                self.other_records_total(),
            ),
        );
        let flush_pct = if self.metrics.records_total > 0 {
            self.metrics.flush_seen as f64 * 100.0 / self.metrics.records_total as f64
        } else {
            0.0
        };
        kv(
            &mut rows,
            "flush-bit / goodbyes",
            format!(
                "{:.0}% flush · {} goodbyes",
                flush_pct, self.metrics.goodbyes_seen
            ),
        );
        let current_q: usize = self
            .services
            .iter()
            .map(|s| s.questions.len())
            .sum::<usize>()
            + self
                .enum_entries
                .iter()
                .map(|e| e.questions.len())
                .sum::<usize>();
        let mut queriers = HashSet::new();
        for s in &self.services {
            for q in &s.questions {
                // Own inferred sends are demand, not queriers.
                if q.2 != SELF_SOURCE {
                    queriers.insert(q.2);
                }
            }
        }
        for e in &self.enum_entries {
            for q in &e.questions {
                if q.2 != SELF_SOURCE {
                    queriers.insert(q.2);
                }
            }
        }
        // One-shot resolvers (§5.1) ask from ephemeral ports; the rest are
        // full queriers on 5353. Quiet when none, to keep the common line.
        let one_shots = queriers
            .iter()
            .filter(|q| anomalies::is_one_shot_querier(q))
            .count();
        let querier_breakdown = if one_shots > 0 {
            format!(", {one_shots} one-shot")
        } else {
            String::new()
        };
        kv(
            &mut rows,
            "questions",
            format!(
                "{current_q} current ({} queriers{querier_breakdown}) · {} ever ({} QU / {} QM) · {} KAs seen",
                queriers.len(),
                self.metrics.questions_total,
                self.metrics.qu_questions_seen,
                self.metrics.qm_questions_seen,
                self.metrics.kas_seen,
            ),
        );

        // Query engine.
        section(&mut rows, "Queries");
        let sent = self.metrics.q_sent_continuous + self.metrics.q_sent_refresh;
        let supp = self.metrics.suppressed_continuous + self.metrics.suppressed_refresh;
        let supp_pct = if sent + supp > 0 {
            supp as f64 * 100.0 / (sent + supp) as f64
        } else {
            0.0
        };
        kv(
            &mut rows,
            "sent",
            format!(
                "{sent} ({} continuous · {} refresh · {} QU)",
                self.metrics.q_sent_continuous, self.metrics.q_sent_refresh, self.metrics.qu_sent
            ),
        );
        kv(
            &mut rows,
            "suppressed queries",
            format!(
                "{supp} total · {} last 60s · {supp_pct:.0}% of due queries asked by a neighbor first",
                self.suppressions_last_60s(),
            ),
        );
        kv(
            &mut rows,
            "KAs attached",
            format!(
                "{} ({:.1}/query)",
                self.metrics.ka_sent,
                if sent > 0 {
                    self.metrics.ka_sent as f64 / sent as f64
                } else {
                    0.0
                }
            ),
        );
        kv(
            &mut rows,
            "continuous interests",
            format!(
                "{} · next in {} · {}",
                self.continuous.len(),
                self.next_continuous_in(),
                self.interval_histogram()
            ),
        );
        kv(
            &mut rows,
            "requeries",
            format!(
                "{} pending · {} overdue · {}",
                self.requeries.len(),
                self.requery_overdue(),
                self.unanswered_histogram()
            ),
        );

        // Links.
        section(&mut rows, "Links");
        kv(&mut rows, "local addrs", self.local_ips.len().to_string());
        let v4names: Vec<String> = self.link_stats.v4.iter().map(|(n, _)| n.clone()).collect();
        let v6names: Vec<String> = self.link_stats.v6.iter().map(|(n, _)| n.clone()).collect();
        if let Some(sel) = &self.interfaces {
            let mut names: Vec<&str> = sel.iter().map(String::as_str).collect();
            names.sort();
            kv(&mut rows, "selected", names.join(", "));
        }
        kv(
            &mut rows,
            "usable v4",
            if v4names.is_empty() {
                "—".to_string()
            } else {
                v4names.join(", ")
            },
        );
        kv(
            &mut rows,
            "usable v6",
            if v6names.is_empty() {
                "—".to_string()
            } else {
                v6names.join(", ")
            },
        );
        kv(
            &mut rows,
            "skipped / inactive",
            format!(
                "{}/{}",
                if self.link_stats.skipped.is_empty() {
                    "—".to_string()
                } else {
                    self.link_stats.skipped.join(", ")
                },
                if self.link_stats.inactive.is_empty() {
                    "—".to_string()
                } else {
                    self.link_stats.inactive.join(", ")
                }
            ),
        );
        kv(
            &mut rows,
            "fan-out per query",
            format!(
                "{} v4 + {} v6 copies",
                v4names.len().max(1),
                v6names.len().max(1)
            ),
        );
        kv(&mut rows, "refused off-link", self.offlink_row());
        kv(&mut rows, "malformed packets", self.malformed_row());
        let mut iface_rows: Vec<(&String, &u64)> = self.metrics.iface_rx.iter().collect();
        iface_rows.sort_by(|a, b| b.1.cmp(a.1).then_with(|| a.0.cmp(b.0)));
        for (iface, count) in iface_rows.iter().take(8) {
            kv(&mut rows, &format!("rx {iface}"), count.to_string());
        }
        if iface_rows.len() > 8 {
            kv(
                &mut rows,
                "rx more links",
                format!("+{} more", iface_rows.len() - 8),
            );
        }
        let mut talkers: Vec<(&std::net::SocketAddr, &u64)> =
            self.metrics.source_rx.iter().collect();
        talkers.sort_by(|a, b| b.1.cmp(a.1));
        for (src, count) in talkers.iter().take(5) {
            kv(&mut rows, &format!("talker {src}"), format!("{count} pkts"));
        }

        // Anomalies last: the list can be long, and the overlay scrolls
        // (j/k, PgUp/PgDn), so every finding is listed instead of capped.
        section(&mut rows, "Anomalies");
        let found = self.anomalies();
        let errors = found
            .iter()
            .filter(|a| matches!(a.severity, anomalies::Severity::Error))
            .count();
        let warnings = found
            .iter()
            .filter(|a| matches!(a.severity, anomalies::Severity::Warning))
            .count();
        let infos = found.len().saturating_sub(errors + warnings);
        kv(
            &mut rows,
            "summary",
            if found.is_empty() {
                "none".to_string()
            } else {
                format!("{errors} error · {warnings} warning · {infos} info")
            },
        );
        // Row identities already claimed in this overlay: repeated
        // identities name their rdata, mirroring the Anomalies pane.
        let identity_count = anomalies::identity_counts(found.iter());
        for a in found.iter() {
            // `<source> <service> <scope> <text>`; unsourced findings omit
            // the source slot, and the key's icon carries the level. The
            // scope helper omits constant/absent row identities and names
            // rdata where siblings share the identity. Every row carries
            // its RFC reference: the key shows no requirement level, and
            // info-level findings surface nowhere else.
            let scope = anomalies::visible_scope(a, &identity_count);
            let scoped = if scope.is_empty() {
                a.message.clone()
            } else {
                format!("{scope}: {}", a.message)
            };
            // `<source> <service> <scope> <text>`; unsourced findings omit
            // the source slot, and the key's icon carries the level. The
            // colon sits before the message when no scope intervenes.
            let sep = if scope.is_empty() { ":" } else { "" };
            let value = match a.source.as_deref() {
                Some(src) => format!("{src}: {}{sep} {scoped} ({})", a.service, a.rfc),
                _ => format!("{}{sep} {scoped} ({})", a.service, a.rfc),
            };
            kv(
                &mut rows,
                &format!(
                    "{} {}",
                    Self::anomaly_level_icon(a.severity),
                    a.kind.as_str()
                ),
                value,
            );
        }

        rows
    }

    fn current_record_liveness(&self) -> (usize, usize, usize) {
        let mut live = 0;
        let mut expired = 0;
        let mut goodbye = 0;
        let mut count = |rec: &browse::RawRecord| match record_liveness(rec) {
            RecordLiveness::Live => live += 1,
            RecordLiveness::Expired => expired += 1,
            RecordLiveness::Goodbye => goodbye += 1,
        };
        for svc in &self.services {
            for rec in &svc.answers {
                count(rec);
            }
        }
        for entry in &self.enum_entries {
            for rec in &entry.answers {
                count(rec);
            }
        }
        (live, expired, goodbye)
    }

    fn other_records_total(&self) -> u64 {
        self.metrics
            .records_by_type
            .iter()
            .filter(|(t, _)| !matches!(**t, 12 | 33 | 16 | 1 | 28))
            .map(|(_, c)| *c)
            .sum()
    }

    fn next_continuous_in(&self) -> String {
        let now = Instant::now();
        self.continuous
            .values()
            .map(|e| e.next_due.saturating_duration_since(now))
            .min()
            .map(|d| {
                if d.as_millis() < 1000 {
                    format!("{}ms", d.as_millis())
                } else {
                    fmt_age(d.as_secs())
                }
            })
            .unwrap_or_else(|| "—".to_string())
    }

    fn interval_histogram(&self) -> String {
        if self.continuous.is_empty() {
            return "no interests".to_string();
        }
        let mut buckets: HashMap<String, usize> = HashMap::new();
        for e in self.continuous.values() {
            let secs = e.interval.as_secs();
            let label = if secs >= 3600 {
                "1h".to_string()
            } else if secs >= 60 {
                format!("{}m", secs / 60)
            } else {
                format!("{secs}s")
            };
            *buckets.entry(label).or_insert(0) += 1;
        }
        let mut items: Vec<(u64, String, usize)> = buckets
            .into_iter()
            .map(|(label, count)| {
                let secs = if label == "1h" {
                    3600
                } else if let Some(m) = label.strip_suffix('m') {
                    m.parse::<u64>().unwrap_or(0) * 60
                } else {
                    label
                        .strip_suffix('s')
                        .unwrap_or(&label)
                        .parse::<u64>()
                        .unwrap_or(0)
                };
                (secs, label, count)
            })
            .collect();
        items.sort_by_key(|(secs, _, _)| *secs);
        items
            .into_iter()
            .map(|(_, label, count)| format!("{label}×{count}"))
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn requery_overdue(&self) -> usize {
        let now = Instant::now();
        self.requeries
            .values()
            .filter(|(due, _)| now >= *due)
            .count()
    }

    fn suppressions_last_60s(&self) -> usize {
        self.metrics
            .suppressed_times
            .iter()
            .filter(|t| t.elapsed() <= Duration::from_secs(60))
            .count()
    }

    /// RFC 6762 §11 refusal counter: unicast-destination packets from
    /// off-link sources, silently discarded by the listeners.
    fn offlink_row(&self) -> String {
        let total = self.drop_stats.total();
        match self.drop_stats.last() {
            Some((src, at)) => format!(
                "{total} total · last {src} {} ago",
                fmt_age(at.elapsed().as_secs())
            ),
            None => format!("{total} total"),
        }
    }

    /// Message-level decode failures: counted in the listener threads so
    /// a garbage storm reads differently from a quiet network.
    fn malformed_row(&self) -> String {
        let total = self.drop_stats.malformed_total();
        match self.drop_stats.malformed_last() {
            Some((src, at)) => format!(
                "{total} total · last {src} {} ago",
                fmt_age(at.elapsed().as_secs())
            ),
            None => format!("{total} total"),
        }
    }

    /// Pure anomaly snapshot over live browser state. Read-only: never
    /// touches query scheduling, ingest, or expiry. Cheap enough to rebuild
    /// per overlay frame (tens of services, hundreds of records).
    /// Flatten one question list into analyzer views, resolving the
    /// displayed type label back to its numeric type. Labels the parser
    /// never emits stay quiet.
    fn push_question_views<'a>(
        out: &mut Vec<anomalies::QuestionView<'a>>,
        service: String,
        rows: &'a [QuestionRow],
    ) {
        for (name, rtype_str, source, _, _) in rows {
            if let Some(rtype) = anomalies::rtype_from_str(rtype_str) {
                out.push(anomalies::QuestionView {
                    service: service.clone(),
                    name,
                    rtype,
                    rtype_str,
                    source: *source,
                });
            }
        }
    }

    pub fn anomalies(&self) -> Vec<anomalies::Anomaly> {
        let mut services: Vec<anomalies::ServiceView<'_>> = self
            .services
            .iter()
            .map(|s| anomalies::ServiceView {
                instance: &s.instance,
                service_type: &s.service_type,
                answers: &s.answers,
                subtypes: &s.subtypes,
            })
            .collect();
        // Pending instances hold PTR/TXT rows that arrived before their
        // SRV: they deserve the same checks. Dedup in the analyzer keeps
        // rows already represented on a confirmed service to one finding;
        // the identity format matches so shared findings collapse.
        for p in &self.pending_instances {
            services.push(anomalies::ServiceView {
                instance: &p.instance,
                service_type: &p.service_type,
                answers: &p.answers,
                subtypes: &p.subtypes,
            });
        }
        let enum_answers: Vec<&browse::RawRecord> = self
            .enum_entries
            .iter()
            .flat_map(|e| e.answers.iter())
            .collect();
        let pending_hosts: HashSet<String> = self.pending_addrs.keys().cloned().collect();
        let address_queries: Vec<_> = self
            .services
            .iter()
            .flat_map(|service| {
                let service_id = anomalies::service_id(&service.instance, &service.service_type);
                let mut targets = HashSet::new();
                for rec in service.answers.iter().filter(|rec| {
                    rec.rtype == 33
                        && rec.ttl > 0
                        && rec.received_at.elapsed().as_secs() <= u64::from(rec.ttl)
                }) {
                    if let Some(host) = rec.rdata.split_whitespace().last() {
                        targets.insert(host.trim_end_matches('.').to_lowercase());
                    }
                }
                targets.into_iter().flat_map(move |hostname| {
                    let service_id = service_id.clone();
                    [1, 28].into_iter().filter_map(move |rtype| {
                        self.query_history
                            .get(&Self::provenance_key(&hostname, rtype))
                            .and_then(|state| state.transmitted.map(|at| (state, at)))
                            .map(|(state, transmitted_at)| anomalies::AddressQueryView {
                                service: service_id.clone(),
                                hostname: hostname.clone(),
                                rtype,
                                transmitted_at,
                                interfaces: state.transmitted_interfaces.clone(),
                            })
                    })
                })
            })
            .collect();
        // Observed questions flattened with their owning service id, so the
        // analyzer can attribute demand-side leaks the same way it does
        // answer sightings. Unrecognised type labels stay quiet.
        let mut questions: Vec<anomalies::QuestionView<'_>> = Vec::new();
        for s in &self.services {
            Self::push_question_views(
                &mut questions,
                anomalies::service_id(&s.instance, &s.service_type),
                &s.questions,
            );
        }
        for p in &self.pending_instances {
            Self::push_question_views(
                &mut questions,
                anomalies::service_id(&p.instance, &p.service_type),
                &p.questions,
            );
        }
        for e in &self.enum_entries {
            Self::push_question_views(
                &mut questions,
                anomalies::ENUMERATION_SERVICE.to_string(),
                &e.questions,
            );
        }
        let snap = anomalies::Snapshot {
            services,
            enum_answers,
            pending_hosts,
            questions,
        };
        anomalies::analyze_observations(&snap, &self.raw_events, &address_queries)
    }

    /// Per-service anomaly counts keyed by `instance.service_type`
    /// service id. Used for host-list markers and the Answers table
    /// without recomputing per row. Informational notes never count.
    pub fn anomaly_counts(&self) -> HashMap<String, usize> {
        let mut counts: HashMap<String, usize> = HashMap::new();
        for a in self.anomalies() {
            if !a.is_surfaced() {
                continue;
            }
            if a.service == anomalies::ENUMERATION_SERVICE {
                continue;
            }
            *counts.entry(a.service.clone()).or_insert(0) += 1;
        }
        counts
    }

    /// Live TXT pairs, deduped and sorted by key (expired and goodbye
    /// rows omitted). High-entropy values are redacted (keys kept) so
    /// dumps are safe to share; dedup runs after redaction so identical
    /// keys collapse to one `key=*REDACTED*` row.
    fn txt_records_for_dump(svc: &ServiceEntry) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut out = Vec::new();
        for rec in &svc.answers {
            if rec.rtype != 16 || rec.ttl == 0 {
                continue;
            }
            if rec.received_at.elapsed().as_secs() as u32 > rec.ttl {
                continue;
            }
            for pair in rec.rdata.split("; ") {
                if pair.is_empty() {
                    continue;
                }
                let redacted = dump::redact_txt_value(pair);
                if seen.insert(redacted.clone()) {
                    out.push(redacted);
                }
            }
        }
        out.sort_by(|a, b| {
            let ka = a.split('=').next().unwrap_or(a);
            let kb = b.split('=').next().unwrap_or(b);
            ka.cmp(kb)
        });
        out
    }

    fn dump_answer_row(rec: &browse::RawRecord) -> dump::DumpAnswer {
        dump::DumpAnswer {
            name: rec.name.clone(),
            rtype: rec.rtype,
            rtype_str: rec.rtype_str.clone(),
            ttl: rec.ttl,
            ttl_remaining: Self::remaining_ttl(rec),
            // High-entropy TXT values and public IPv6 literals are
            // redacted for safe sharing.
            rdata: if rec.rtype == 16 {
                dump::redact_txt_rdata(&rec.rdata)
            } else if rec.rtype == 28 {
                dump::redact_ip_literal(&rec.rdata)
            } else {
                rec.rdata.clone()
            },
            source: rec.source.to_string(),
            iface: rec.iface.clone(),
            ifindex: rec.ifindex,
            flush: rec.flush_bit,
            section: format!("{:?}", rec.section).to_lowercase(),
            multicast_dst: rec.dst_is_multicast,
            received_at: dump::instant_to_iso(rec.received_at),
            age_secs: rec.received_at.elapsed().as_secs(),
        }
    }

    fn dump_question_row(q: &QuestionRow) -> dump::DumpQuestion {
        dump::DumpQuestion {
            name: q.0.clone(),
            rtype_str: q.1.clone(),
            source: q.2.to_string(),
            received_at: dump::instant_to_iso(q.3),
            age_secs: q.3.elapsed().as_secs(),
        }
    }

    fn dump_service(&self, svc: &ServiceEntry) -> dump::DumpService {
        let mut subtypes: Vec<String> = svc
            .subtypes
            .iter()
            .map(|subtype| anomalies::display_subtype(subtype))
            .collect();
        subtypes.sort();
        // Public IPv6 literals keep first/last hextet only; identical
        // markers dedup here.
        let mut seen_addrs = HashSet::new();
        let mut addresses = Vec::new();
        for addr in self.host_addresses(&Self::host_key(&svc.hostname)) {
            let redacted = dump::redact_ip_literal(&addr);
            if seen_addrs.insert(redacted.clone()) {
                addresses.push(redacted);
            }
        }
        dump::DumpService {
            instance: svc.instance.clone(),
            service_type: svc.service_type.clone(),
            hostname: svc.hostname.clone(),
            port: svc.port,
            addresses,
            txt_records: Self::txt_records_for_dump(svc),
            is_active: svc.is_active,
            last_seen_age_secs: svc.last_seen.elapsed().as_secs(),
            subtypes,
            answers: svc
                .ordered_answers()
                .into_iter()
                .map(Self::dump_answer_row)
                .collect(),
            questions: svc.questions.iter().map(Self::dump_question_row).collect(),
            questions_truncated: svc.questions_dropped > 0,
            questions_dropped: svc.questions_dropped,
        }
    }

    /// Snapshot of mex's own browse state.
    fn state_dump(&self) -> dump::StateDump {
        let mut service_types: Vec<String> = self.known_types.iter().cloned().collect();
        service_types.sort();
        let mut metrics = std::collections::BTreeMap::new();
        let m = &self.metrics;
        metrics.insert("packets".to_string(), self.packet_count);
        metrics.insert("bytes_total".to_string(), m.bytes_total);
        metrics.insert("records_total".to_string(), m.records_total);
        for (t, label) in [
            (12, "ptr"),
            (33, "srv"),
            (16, "txt"),
            (1, "a"),
            (28, "aaaa"),
        ] {
            metrics.insert(
                format!("records_{label}"),
                m.records_by_type.get(&t).copied().unwrap_or(0),
            );
        }
        metrics.insert("records_other".to_string(), self.other_records_total());
        metrics.insert("questions_total".to_string(), m.questions_total);
        metrics.insert("questions_qu".to_string(), m.qu_questions_seen);
        metrics.insert("questions_qm".to_string(), m.qm_questions_seen);
        metrics.insert("kas_seen".to_string(), m.kas_seen);
        metrics.insert("goodbyes_seen".to_string(), m.goodbyes_seen);
        metrics.insert("flush_seen".to_string(), m.flush_seen);
        metrics.insert("q_sent_continuous".to_string(), m.q_sent_continuous);
        metrics.insert("q_sent_refresh".to_string(), m.q_sent_refresh);
        metrics.insert("qu_sent".to_string(), m.qu_sent);
        metrics.insert("ka_sent".to_string(), m.ka_sent);
        metrics.insert("suppressed_continuous".to_string(), m.suppressed_continuous);
        metrics.insert("suppressed_refresh".to_string(), m.suppressed_refresh);
        metrics.insert(
            "pending_addrs".to_string(),
            self.pending_addrs_count() as u64,
        );
        metrics.insert("services_current".to_string(), self.services.len() as u64);
        metrics.insert(
            "services_active".to_string(),
            self.services.iter().filter(|s| s.is_active).count() as u64,
        );
        metrics.insert("services_seen_total".to_string(), m.services_seen_total);
        metrics.insert(
            "services_expired_total".to_string(),
            m.services_expired_total,
        );
        metrics.insert("service_types".to_string(), service_types.len() as u64);
        metrics.insert("enum_known".to_string(), self.enum_known.len() as u64);
        metrics.insert(
            "continuous_interests".to_string(),
            self.continuous.len() as u64,
        );
        metrics.insert("requery_pending".to_string(), self.requeries.len() as u64);
        metrics.insert(
            "uptime_secs".to_string(),
            self.start_time.elapsed().as_secs(),
        );
        let now = Instant::now();
        let mut interest_keys: HashSet<(String, u16)> =
            self.query_history.keys().cloned().collect();
        for key in self.requeries.keys() {
            interest_keys.insert(Self::provenance_key(&key.0, key.1));
        }
        for key in self.continuous.keys() {
            interest_keys.insert(Self::provenance_key(&key.0, key.1));
        }
        // Answer-only interests (e.g. passive captures, answers without
        // any observed query): provenance and schedules know nothing
        // about them, but the dump must still list what was retained.
        // Origin stays absent rather than invented.
        let mut answer_key = |name: &str, rtype: u16| {
            interest_keys.insert(Self::provenance_key(name, rtype));
        };
        for svc in &self.services {
            for rec in &svc.answers {
                answer_key(&rec.name, rec.rtype);
            }
        }
        for entry in &self.enum_entries {
            for rec in &entry.answers {
                answer_key(&rec.name, rec.rtype);
            }
        }
        for p in &self.pending_instances {
            for rec in &p.answers {
                answer_key(&rec.name, rec.rtype);
            }
        }
        for recs in self.pending_addrs.values() {
            for rec in recs {
                answer_key(&rec.name, rec.rtype);
            }
        }
        let mut interest_keys: Vec<(String, u16)> = interest_keys.into_iter().collect();
        interest_keys.sort();
        let interests = interest_keys
            .iter()
            .map(|key| {
                let view = self.interest_view(key);
                dump::DumpInterest {
                    name: key.0.clone(),
                    rtype: key.1,
                    rtype_str: browse::rtype_label(key.1),
                    timer: view.timer.as_str().to_string(),
                    status: view.status.as_str().to_string(),
                    attempt: view.attempt,
                    next_due_in_secs: view
                        .next_due
                        .map(|d| d.saturating_duration_since(now).as_secs()),
                    last_origin: view.origin().map(|o| o.as_str().to_string()),
                    last_event_age_secs: view
                        .last_at()
                        .map(|t| now.saturating_duration_since(t).as_secs()),
                    last_transmitted_age_secs: view
                        .at(QueryOrigin::Transmitted)
                        .map(|t| now.saturating_duration_since(t).as_secs()),
                    last_suppressed_age_secs: view
                        .at(QueryOrigin::Suppressed)
                        .map(|t| now.saturating_duration_since(t).as_secs()),
                    last_observed_age_secs: view
                        .at(QueryOrigin::Observed)
                        .map(|t| now.saturating_duration_since(t).as_secs()),
                    last_observed_from: view.observed().map(|o| o.from.to_string()),
                    last_observed_iface: view.observed().map(|o| o.iface.clone()),
                }
            })
            .collect();
        let found = self.anomalies();
        metrics.insert("anomalies_total".to_string(), found.len() as u64);
        metrics.insert(
            "anomalies_error".to_string(),
            found
                .iter()
                .filter(|a| matches!(a.severity, anomalies::Severity::Error))
                .count() as u64,
        );
        metrics.insert(
            "anomalies_warning".to_string(),
            found
                .iter()
                .filter(|a| matches!(a.severity, anomalies::Severity::Warning))
                .count() as u64,
        );
        metrics.insert(
            "malformed_packets".to_string(),
            self.drop_stats.malformed_total(),
        );
        dump::StateDump {
            metadata: dump::Metadata {
                dump_timestamp: dump::dump_timestamp_iso(),
                application_name: "mex".to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            services: self.services.iter().map(|s| self.dump_service(s)).collect(),
            service_types,
            metrics,
            passive: self.passive,
            enum_groups: self
                .enum_entries
                .iter()
                .map(|e| dump::RawGroup {
                    name: e.name.clone(),
                    answers: e.answers.iter().map(Self::dump_answer_row).collect(),
                    questions: e.questions.iter().map(Self::dump_question_row).collect(),
                    questions_truncated: e.questions_dropped > 0,
                    questions_dropped: e.questions_dropped,
                })
                .collect(),
            pending: self
                .pending_instances
                .iter()
                .map(|p| dump::RawGroup {
                    name: format!("{}.{}", p.instance, p.service_type),
                    answers: p.answers.iter().map(Self::dump_answer_row).collect(),
                    questions: p.questions.iter().map(Self::dump_question_row).collect(),
                    questions_truncated: p.questions_dropped > 0,
                    questions_dropped: p.questions_dropped,
                })
                .collect(),
            interests,
            anomalies: found
                .iter()
                .map(|a| dump::DumpAnomaly {
                    kind: a.kind.as_str().to_string(),
                    severity: a.severity.as_str().to_string(),
                    service: a.service.clone(),
                    record_name: a.record_name.clone(),
                    rtype: a.rtype,
                    rtype_str: a.rtype_str.clone(),
                    // Reuse the safe-sharing redaction policy: TXT pairs
                    // redacted, public IPv6 literals masked.
                    rdata: a.rdata.clone().map(|d| match a.rtype {
                        Some(16) => dump::redact_txt_rdata(&d),
                        Some(28) => dump::redact_ip_literal(&d),
                        _ => d,
                    }),
                    source: a.source.clone(),
                    message: a.message.clone(),
                    rfc: a.rfc.to_string(),
                    requirement: a.requirement.to_string(),
                })
                .collect(),
        }
    }

    fn save_state_dump(&self) -> Result<String> {
        let json_path = self.save_state_dump_to(std::path::Path::new(""))?;
        Ok(json_path.to_string_lossy().into_owned())
    }

    fn save_state_dump_to(&self, dir: &std::path::Path) -> Result<std::path::PathBuf> {
        let json = serde_json::to_string_pretty(&self.state_dump())?;
        let stem = dump::file_stem_iso();
        let json_path = dir.join(format!(
            "{stem}-{appname}-{version}.json",
            appname = env!("CARGO_PKG_NAME"),
            version = env!("CARGO_PKG_VERSION")
        ));
        std::fs::write(&json_path, &json)?;
        Ok(json_path)
    }

    /// Confirmation popup text while fresh (3s); `None` once expired.
    pub fn status_popup(&self) -> Option<String> {
        let (text, since) = self.status_msg.as_ref()?;
        if since.elapsed() <= Duration::from_secs(3) {
            Some(text.clone())
        } else {
            None
        }
    }

    fn unanswered_histogram(&self) -> String {
        if self.requeries.is_empty() {
            return "none unanswered".to_string();
        }
        let mut counts = [0usize; 4];
        for (_, c) in self.requeries.values() {
            let idx = usize::from((*c).min(4).saturating_sub(1).min(3));
            counts[idx] += 1;
        }
        format!(
            "miss×1:{} ×2:{} ×3:{} ×4:{}",
            counts[0], counts[1], counts[2], counts[3]
        )
    }

    fn toggle_collapse(&mut self) {
        let items = self.display_items();
        match items.get(self.selected_display) {
            Some(DisplayItem::Host { label }) => {
                let label = label.clone();
                if !self.collapsed_hosts.remove(&label) {
                    self.collapsed_hosts.insert(label);
                }
            }
            // Hostname is folded into the host header, so +/- on an
            // instance folds its parent host.
            Some(DisplayItem::Instance { index }) => {
                let label = Self::host_key(&self.services[*index].hostname);
                if !self.collapsed_hosts.remove(&label) {
                    self.collapsed_hosts.insert(label);
                }
            }
            Some(DisplayItem::Enum { .. }) => {
                let label = ENUM_HOST.to_string();
                if !self.collapsed_hosts.remove(&label) {
                    self.collapsed_hosts.insert(label);
                }
            }
            None => {}
        }
        self.clamp_selection();
    }

    /// `*` toggles every host group at once: unfold all when all are
    /// collapsed, collapse all otherwise (so one press always lands in
    /// a uniform state). Works from any pane.
    fn toggle_collapse_all(&mut self) {
        let labels = self.group_labels();
        if labels.iter().all(|l| self.collapsed_hosts.contains(l)) {
            self.collapsed_hosts.clear();
        } else {
            self.collapsed_hosts.extend(labels);
        }
        self.clamp_selection();
    }

    /// Ctrl+Z suspends the process on unix: raw mode disables ISIG, so the
    /// terminal stop key arrives as a key event instead of SIGTSTP.
    /// Lowercase only, mirroring the sibling mdns-tui-browser binding.
    #[cfg(unix)]
    fn is_suspend_key(key: &KeyEvent) -> bool {
        key.code == KeyCode::Char('z') && key.modifiers.contains(KeyModifiers::CONTROL)
    }

    fn handle_key(&mut self, key: &KeyEvent) {
        // Ctrl+C quits: raw mode turns it into a key event (no SIGINT).
        if key.code == KeyCode::Char('c') && key.modifiers.contains(KeyModifiers::CONTROL) {
            self.running = false;
            return;
        }
        // Experimental dump of mex's own browse state (Ctrl+J).
        // This takes Ctrl+J away from detail scrolling (Ctrl+K still
        // scrolls; the other scroll keys are unaffected).
        if key.modifiers.contains(KeyModifiers::CONTROL)
            && matches!(key.code, KeyCode::Char('j') | KeyCode::Char('J'))
        {
            let msg = match self.save_state_dump() {
                Ok(json) => {
                    log::info!("mex: state dump saved to {json}");
                    format!("Dump saved: {json}")
                }
                Err(e) => {
                    log::error!("mex: state dump failed: {e:#}");
                    format!("Dump failed: {e:#}")
                }
            };
            self.status_msg = Some((msg, Instant::now()));
            return;
        }
        // Any other key dismisses a visible confirmation popup.
        self.status_msg = None;
        let no_ctrl_alt = !key
            .modifiers
            .intersects(KeyModifiers::CONTROL | KeyModifiers::ALT);
        // `m` toggles the metrics overlay from anywhere.
        if no_ctrl_alt && matches!(key.code, KeyCode::Char('m') | KeyCode::Char('M')) {
            self.show_metrics = !self.show_metrics;
            if self.show_metrics {
                self.metrics_scroll.set(0);
                self.metrics_hscroll.set(0);
                // The overlay owns all input while open: drop any active
                // resize so borders behind it never glow.
                self.drag = DragMode::None;
                self.hover.set(DragMode::None);
            }
            return;
        }
        // While the overlay is open it owns every key except Ctrl+C:
        // `m`/`Esc` closes, `q` quits, the rest scrolls. Uppercase and
        // lowercase + SHIFT report the same intent on all protocols.
        if self.show_metrics {
            match key.code {
                KeyCode::Esc => self.show_metrics = false,
                KeyCode::Char('q') => self.running = false,
                KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') => self.scroll_metrics(-1),
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => self.scroll_metrics(1),
                KeyCode::Home => self.scroll_metrics_edge(true),
                KeyCode::End => self.scroll_metrics_edge(false),
                KeyCode::PageUp | KeyCode::Char('b') => self.page_metrics(-1),
                KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => self.page_metrics(1),
                // Horizontal pan over long values (key column stays
                // frozen): Ctrl jumps ten chars, `0` jumps back.
                KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('H') => {
                    self.scroll_metrics_h(if key.modifiers.contains(KeyModifiers::CONTROL) {
                        -10
                    } else {
                        -1
                    })
                }
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('L') => {
                    self.scroll_metrics_h(if key.modifiers.contains(KeyModifiers::CONTROL) {
                        10
                    } else {
                        1
                    })
                }
                KeyCode::Char('0') => self.metrics_hscroll.set(0),
                _ => {}
            }
            return;
        }
        // `*` folds/unfolds all host groups from any pane.
        if no_ctrl_alt && matches!(key.code, KeyCode::Char('*')) {
            self.toggle_collapse_all();
            return;
        }
        // Tab cycles pane focus in both directions.
        match key.code {
            KeyCode::Tab => {
                self.focus = match self.focus {
                    Focus::Services => Focus::Answers,
                    Focus::Answers => Focus::Questions,
                    Focus::Questions => Focus::Anomalies,
                    Focus::Anomalies => Focus::Hex,
                    Focus::Hex => Focus::Services,
                };
                self.snap_detail_to_focus();
                return;
            }
            KeyCode::BackTab => {
                self.focus = match self.focus {
                    Focus::Services => Focus::Hex,
                    Focus::Answers => Focus::Services,
                    Focus::Questions => Focus::Answers,
                    Focus::Anomalies => Focus::Questions,
                    Focus::Hex => Focus::Anomalies,
                };
                self.snap_detail_to_focus();
                return;
            }
            _ => {}
        }
        match key.code {
            KeyCode::Char('q') | KeyCode::Esc => self.running = false,
            // Detail viewport scroll works from either pane: the Answers
            // table, or the Hex dump while it holds focus.
            KeyCode::Up | KeyCode::Down
                if key.modifiers.contains(KeyModifiers::CONTROL)
                    || key.modifiers.contains(KeyModifiers::SHIFT) =>
            {
                self.scroll_focused_detail(if key.code == KeyCode::Down { 1 } else { -1 })
            }
            KeyCode::Char('j') | KeyCode::Char('k')
                if key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.scroll_focused_detail(if key.code == KeyCode::Char('j') {
                    1
                } else {
                    -1
                })
            }
            KeyCode::Char('J') => self.scroll_focused_detail(1),
            KeyCode::Char('K') => self.scroll_focused_detail(-1),
            // Shifted j/k reported lowercase + SHIFT (some keyboard
            // protocols) scroll too; they must never move the cursor.
            KeyCode::Char('j') | KeyCode::Char('k')
                if key.modifiers.contains(KeyModifiers::SHIFT)
                    && !key.modifiers.contains(KeyModifiers::CONTROL) =>
            {
                self.scroll_focused_detail(if key.code == KeyCode::Char('j') {
                    1
                } else {
                    -1
                })
            }
            _ => self.handle_focused_key(key),
        }
    }

    /// Percent range kept for the Hosts pane; the detail side always keeps
    /// the remainder, so tiny terminals cannot collapse either side away.
    fn clamp_left_pct(pct: u16) -> u16 {
        pct.clamp(15, 80)
    }

    /// Answers/Questions/Anomalies shares keep at least 10% each and leave
    /// at least 10% for the hex pane (`answers + questions + anomalies <=
    /// 90`). The second argument is the sum of the other two shares.
    fn clamp_pane_pct(pct: u16, others: u16) -> u16 {
        let max = 90u16.saturating_sub(others).max(10);
        pct.clamp(10, 70).min(max)
    }

    fn pct_from_x(col: u16, body: Rect) -> u16 {
        if body.width == 0 {
            return 33;
        }
        (col.saturating_sub(body.x) as u32 * 100 / body.width.max(1) as u32).min(100) as u16
    }

    fn pct_from_y(row: u16, right: Rect) -> u16 {
        if right.height == 0 {
            return 34;
        }
        (row.saturating_sub(right.y) as u32 * 100 / right.height.max(1) as u32).min(100) as u16
    }

    fn point_in(rect: Rect, col: u16, row: u16) -> bool {
        rect.width > 0
            && rect.height > 0
            && col >= rect.x
            && col < rect.x.saturating_add(rect.width)
            && row >= rect.y
            && row < rect.y.saturating_add(rect.height)
    }

    /// Shared pane border under the cursor, if any. With no gutter the
    /// two abutting border cells form a 2-cell grab zone: the Hosts
    /// right edge / detail left edge vertically, and the Answers bottom
    /// / Questions top, Questions bottom / Anomalies top, then Anomalies
    /// bottom / Hex top horizontally.
    /// Seams win over panes so the border stays grabbable.
    fn divider_at(&self, col: u16, row: u16) -> DragMode {
        let left = self.left_rect.get();
        let right = self.right_rect.get();
        if left.width > 0 && right.width > 0 {
            let left_edge = left.x.saturating_add(left.width.saturating_sub(1));
            if (col == left_edge || col == right.x)
                && row >= left.y
                && row < left.y.saturating_add(left.height)
            {
                return DragMode::Vertical;
            }
        }
        let answers = self.answers_rect.get();
        let questions = self.questions_rect.get();
        let anomalies = self.anomalies_rect.get();
        if answers.height > 0 && questions.height > 0 {
            let bottom = answers.y.saturating_add(answers.height.saturating_sub(1));
            if (row == bottom || row == questions.y)
                && col >= answers.x
                && col < answers.x.saturating_add(answers.width)
            {
                return DragMode::HorizUpper;
            }
        }
        if questions.height > 0 && anomalies.height > 0 {
            let bottom = questions
                .y
                .saturating_add(questions.height.saturating_sub(1));
            if (row == bottom || row == anomalies.y)
                && col >= questions.x
                && col < questions.x.saturating_add(questions.width)
            {
                return DragMode::HorizMiddle;
            }
        }
        let hex = self.hex_rect.get();
        if anomalies.height > 0 && hex.height > 0 {
            let bottom = anomalies
                .y
                .saturating_add(anomalies.height.saturating_sub(1));
            if (row == bottom || row == hex.y)
                && col >= anomalies.x
                && col < anomalies.x.saturating_add(anomalies.width)
            {
                return DragMode::HorizLower;
            }
        }
        DragMode::None
    }

    fn set_left_from_x(&mut self, col: u16) {
        let pct = Self::pct_from_x(col, self.body_rect.get());
        self.left_pct = Self::clamp_left_pct(pct);
    }

    fn set_answers_from_y(&mut self, row: u16) {
        let pct = Self::pct_from_y(row, self.right_rect.get());
        self.answers_pct = Self::clamp_pane_pct(pct, self.questions_pct + self.anomalies_pct);
    }

    fn set_middle_from_y(&mut self, row: u16) {
        let combined = Self::pct_from_y(row, self.right_rect.get());
        let want = combined.saturating_sub(self.answers_pct);
        self.questions_pct = Self::clamp_pane_pct(want, self.answers_pct + self.anomalies_pct);
    }

    fn set_lower_from_y(&mut self, row: u16) {
        let combined = Self::pct_from_y(row, self.right_rect.get());
        let want = combined.saturating_sub(self.answers_pct + self.questions_pct);
        self.anomalies_pct = Self::clamp_pane_pct(want, self.answers_pct + self.questions_pct);
    }

    fn handle_mouse(&mut self, mouse: &MouseEvent) {
        match mouse.kind {
            MouseEventKind::Down(MouseButton::Left) => {
                self.mouse_down(mouse.column, mouse.row);
            }
            MouseEventKind::Drag(MouseButton::Left) => {
                self.mouse_drag(mouse.column, mouse.row);
            }
            MouseEventKind::Moved => {
                self.mouse_moved(mouse.column, mouse.row);
            }
            MouseEventKind::Up(MouseButton::Left) => {
                self.drag = DragMode::None;
            }
            MouseEventKind::ScrollDown => self.mouse_wheel(1),
            MouseEventKind::ScrollUp => self.mouse_wheel(-1),
            MouseEventKind::ScrollLeft => self.mouse_hwheel(-1),
            MouseEventKind::ScrollRight => self.mouse_hwheel(1),
            _ => {}
        }
    }

    /// Wheel notch: exactly one j/k press in the focused pane. Cursor panes
    /// move the cursor (the hex dump follows); free-scroll panes nudge the
    /// viewport. The metrics overlay owns the wheel while open.
    fn mouse_wheel(&mut self, delta: isize) {
        if self.show_metrics {
            self.scroll_metrics(delta);
            return;
        }
        match self.focus {
            Focus::Services => self.move_selection(delta),
            Focus::Answers | Focus::Questions => self.move_detail_cursor(delta),
            Focus::Anomalies => self.scroll_anomalies(delta),
            Focus::Hex => self.scroll_hex(delta),
        }
    }

    /// Horizontal wheel notch: pans metrics values while the overlay is
    /// open, ignored everywhere else.
    fn mouse_hwheel(&mut self, delta: isize) {
        if self.show_metrics {
            self.scroll_metrics_h(delta);
        }
    }

    fn mouse_down(&mut self, col: u16, row: u16) {
        // The metrics overlay owns all input while open (closed via m/Esc).
        if self.show_metrics {
            return;
        }
        match self.divider_at(col, row) {
            DragMode::None => {}
            mode => {
                self.drag = mode;
                self.hover.set(mode);
                return;
            }
        }
        if Self::point_in(self.left_rect.get(), col, row) {
            self.click_service_list(row);
        } else if Self::point_in(self.answers_rect.get(), col, row) {
            self.click_answers(row);
        } else if Self::point_in(self.questions_rect.get(), col, row) {
            self.click_questions(row);
        } else if Self::point_in(self.anomalies_rect.get(), col, row) {
            // The anomalies pane follows the cursor; clicking focuses
            // it so its keys scroll the findings.
            self.focus = Focus::Anomalies;
        } else if Self::point_in(self.hex_rect.get(), col, row) {
            // The hex pane follows the cursor; clicking focuses it so its
            // keys scroll the dump.
            self.focus = Focus::Hex;
            self.click_hex_field(col, row);
        }
    }

    fn click_hex_field(&self, col: u16, row: u16) {
        if let Some((_, index)) = self
            .hex_field_hits
            .borrow()
            .iter()
            .find(|(rect, _)| col >= rect.x && col < rect.x + rect.width && row == rect.y)
        {
            self.hex_selected_field.set(Some(*index));
        }
    }

    fn mouse_drag(&mut self, col: u16, row: u16) {
        // The metrics overlay owns all input while open (closed via m/Esc).
        if self.show_metrics {
            return;
        }
        match self.drag {
            DragMode::Vertical => {
                self.set_left_from_x(col);
                self.hover.set(DragMode::Vertical);
            }
            DragMode::HorizUpper => {
                self.set_answers_from_y(row);
                self.hover.set(DragMode::HorizUpper);
            }
            DragMode::HorizMiddle => {
                self.set_middle_from_y(row);
                self.hover.set(DragMode::HorizMiddle);
            }
            DragMode::HorizLower => {
                self.set_lower_from_y(row);
                self.hover.set(DragMode::HorizLower);
            }
            DragMode::None => {
                self.hover.set(self.divider_at(col, row));
            }
        }
    }

    fn mouse_moved(&mut self, col: u16, row: u16) {
        // The metrics overlay owns all input while open (closed via m/Esc).
        if self.show_metrics {
            return;
        }
        // Some terminals report drags as Moved; keep following the active
        // divider in that case.
        if self.drag != DragMode::None {
            self.mouse_drag(col, row);
        } else {
            self.hover.set(self.divider_at(col, row));
        }
    }

    /// Click in the Hosts pane: instances select, headers fold. Mirrors the
    /// keyboard rule that expanded headers are not selectable stops.
    fn click_service_list(&mut self, row: u16) {
        self.focus = Focus::Services;
        let area = self.left_rect.get();
        if area.height < 3
            || row <= area.y
            || row >= area.y.saturating_add(area.height).saturating_sub(1)
        {
            return;
        }
        let rel = row.saturating_sub(area.y.saturating_add(1)) as usize;
        let idx = self.list_offset.get().saturating_add(rel);
        let items = self.display_items();
        let Some(item) = items.get(idx) else {
            return;
        };
        match item {
            DisplayItem::Instance { .. } | DisplayItem::Enum { .. } => {
                self.selected_display = idx;
                self.clamp_selection();
            }
            DisplayItem::Host { label } => {
                let label = label.clone();
                // Capture the selected item first: folding below the cursor
                // removes rows and unfolding above it inserts them, so the
                // raw index is stale after the toggle either way.
                let prev = items.get(self.selected_display).cloned();
                if !self.collapsed_hosts.remove(&label) {
                    self.collapsed_hosts.insert(label);
                }
                let items = self.display_items();
                let mut restored = false;
                if let Some(p) = prev {
                    if let Some(pos) = items.iter().position(|it| *it == p) {
                        // Same item, new row: selecting the clicked header
                        // can wait for clamp_selection below.
                        self.selected_display = pos;
                        restored = true;
                    }
                }
                // Only fall back to the clicked header when the previous
                // selection folded away with its group: it is selectable
                // exactly when the click just collapsed its host.
                if !restored
                    && matches!(items.get(idx), Some(DisplayItem::Host { .. }))
                    && self.is_selectable(&items[idx])
                {
                    self.selected_display = idx;
                }
                self.clamp_selection();
            }
        }
    }

    /// Map an Answers table row (including info/child rows) to the detail
    /// cursor index. Child rows select their parent record; info rows
    /// select nothing. Mirrors `detail_table_rows` in `ui.rs`.
    fn answers_table_row_to_detail(&self, table_row: usize) -> Option<usize> {
        let target = self.display_detail()?;
        let info_rows = match &target {
            DetailTarget::Service(svc) => {
                let mut seen = HashSet::new();
                let mut subs = 0;
                for sub in &svc.subtypes {
                    if seen.insert(sub) {
                        subs += 1;
                    }
                }
                1 + subs
            }
            DetailTarget::Enum(_) => 1,
        };
        if table_row < info_rows {
            return None;
        }
        let mut row = info_rows;
        for (idx, rec) in target.ordered_answers().into_iter().enumerate() {
            if table_row == row {
                return Some(idx);
            }
            let children = if self.is_txt_expanded(rec) {
                let pairs = Self::txt_pair_count(&rec.rdata);
                if pairs > 1 {
                    pairs
                } else {
                    0
                }
            } else {
                0
            };
            // Child rows belong to the parent record.
            if table_row > row && table_row <= row + children {
                return Some(idx);
            }
            row += 1 + children;
        }
        None
    }

    fn click_answers(&mut self, row: u16) {
        self.focus = Focus::Answers;
        let area = self.answers_rect.get();
        if area.height < 3 || row < area.y.saturating_add(2) {
            return;
        }
        if row >= area.y.saturating_add(area.height).saturating_sub(1) {
            return;
        }
        let rel = row.saturating_sub(area.y.saturating_add(2)) as usize;
        let table_row = self.detail_offset.get().saturating_add(rel);
        if let Some(idx) = self.answers_table_row_to_detail(table_row) {
            // Stay on the clicked target: the cursor follows the click
            // instead of the manual-scroll viewport. A new row also
            // restarts the hex dump at the top and scrolls the
            // anomalies pane to the row's finding.
            self.detail_free_scroll = false;
            if self.detail_selected != idx {
                self.detail_selected = idx;
                self.restart_for_new_row();
            }
            self.detail_anchor = self
                .display_detail()
                .and_then(|d| Self::identity_at_detail(&d, self.detail_selected));
        }
    }

    fn click_questions(&mut self, row: u16) {
        self.focus = Focus::Questions;
        let area = self.questions_rect.get();
        if area.height < 3 || row < area.y.saturating_add(2) {
            return;
        }
        if row >= area.y.saturating_add(area.height).saturating_sub(1) {
            return;
        }
        let rel = row.saturating_sub(area.y.saturating_add(2)) as usize;
        let Some(target) = self.display_detail() else {
            return;
        };
        let raws = target.ordered_answers().len();
        let table_row = self.questions_offset.get().saturating_add(rel);
        if table_row < target.questions_len() {
            self.detail_free_scroll = false;
            let idx = raws + table_row;
            if self.detail_selected != idx {
                self.detail_selected = idx;
                self.restart_for_new_row();
            }
            self.detail_anchor = self
                .display_detail()
                .and_then(|d| Self::identity_at_detail(&d, self.detail_selected));
        }
    }

    /// Cursor keys routed to the focused pane. Tab switches panes; arrows
    /// and j/k navigate inside the focused pane.
    fn handle_focused_key(&mut self, key: &KeyEvent) {
        match self.focus {
            Focus::Services => match key.code {
                KeyCode::Up => self.move_selection(-1),
                KeyCode::Down => self.move_selection(1),
                KeyCode::Char('k') => self.move_selection(-1),
                KeyCode::Char('j') => self.move_selection(1),
                // Jump between host groups.
                KeyCode::Char('h') | KeyCode::Left => self.jump_group(-1),
                KeyCode::Char('l') | KeyCode::Right => self.jump_group(1),
                // Shift jumps to the first/last group (uppercase from Shift).
                KeyCode::Char('H') => self.jump_group_edge(true),
                KeyCode::Char('L') => self.jump_group_edge(false),
                KeyCode::Home => self.select_edge(true),
                KeyCode::End => self.select_edge(false),
                KeyCode::PageUp | KeyCode::Char('b') => self.page_selection(-1),
                KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => {
                    self.page_selection(1)
                }
                // Enter folds the host like +/- does.
                KeyCode::Enter => self.toggle_collapse(),
                KeyCode::Char('+') | KeyCode::Char('-') => self.toggle_collapse(),
                _ => {}
            },
            Focus::Answers => match key.code {
                KeyCode::Up => self.move_detail_cursor(-1),
                KeyCode::Down => self.move_detail_cursor(1),
                KeyCode::Char('k') => self.move_detail_cursor(-1),
                KeyCode::Char('j') => self.move_detail_cursor(1),
                KeyCode::Home => self.move_detail_edge(true),
                KeyCode::End => self.move_detail_edge(false),
                KeyCode::PageUp | KeyCode::Char('b') => self.page_detail(-1),
                KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => self.page_detail(1),
                // Enter folds/unfolds the TXT record under the cursor.
                KeyCode::Enter => {
                    self.toggle_txt_expanded();
                }
                _ => {}
            },
            Focus::Questions => match key.code {
                KeyCode::Up => self.move_detail_cursor(-1),
                KeyCode::Down => self.move_detail_cursor(1),
                KeyCode::Char('k') => self.move_detail_cursor(-1),
                KeyCode::Char('j') => self.move_detail_cursor(1),
                KeyCode::Home => self.move_detail_edge(true),
                KeyCode::End => self.move_detail_edge(false),
                KeyCode::PageUp | KeyCode::Char('b') => self.page_detail(-1),
                KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => self.page_detail(1),
                _ => {}
            },
            // The hex and anomalies panes have no cursor; their keys scroll
            // the dumps, which follow the record cursor.
            Focus::Hex => match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.scroll_hex(-1),
                KeyCode::Down | KeyCode::Char('j') => self.scroll_hex(1),
                KeyCode::Home => self.scroll_hex_edge(true),
                KeyCode::End => self.scroll_hex_edge(false),
                KeyCode::PageUp | KeyCode::Char('b') => self.page_hex(-1),
                KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => self.page_hex(1),
                _ => {}
            },
            Focus::Anomalies => match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.scroll_anomalies(-1),
                KeyCode::Down | KeyCode::Char('j') => self.scroll_anomalies(1),
                KeyCode::Home => self.scroll_anomalies_edge(true),
                KeyCode::End => self.scroll_anomalies_edge(false),
                KeyCode::PageUp | KeyCode::Char('b') => self.page_anomalies(-1),
                KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => {
                    self.page_anomalies(1)
                }
                _ => {}
            },
        }
    }

    /// Selectable stops for Up/Down: instances always, host
    /// headers only while collapsed (so a collapsed host can be
    /// uncollapsed again; folding is also available from member rows).
    fn is_selectable(&self, item: &DisplayItem) -> bool {
        match item {
            DisplayItem::Instance { .. } | DisplayItem::Enum { .. } => true,
            DisplayItem::Host { label } => self.collapsed_hosts.contains(label),
        }
    }

    /// First/last selectable stop.
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

    /// Page the service selection by one viewport of stops
    /// (PageUp/PageDown/b/f/Space). Falls back to 10 stops before the
    /// first draw answers the real height.
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

    /// Host group keys in display order.
    fn group_labels(&self) -> Vec<String> {
        let mut labels = Vec::new();
        for it in self.display_items() {
            if let DisplayItem::Host { label } = it {
                if !labels.contains(&label) {
                    labels.push(label);
                }
            }
        }
        labels
    }

    /// Key of the host group containing the cursor row.
    fn cursor_group(&self) -> Option<String> {
        match self.display_items().get(self.selected_display)? {
            DisplayItem::Host { label } => Some(label.clone()),
            DisplayItem::Instance { index } => {
                Some(Self::host_key(&self.services[*index].hostname))
            }
            DisplayItem::Enum { .. } => Some(ENUM_HOST.to_string()),
        }
    }

    /// Jump to the neighbouring host group, landing on its first
    /// selectable stop.
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

    /// Jump to the first/last host group (Shift+h/l).
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

    /// Select the first selectable stop of a host group: its header while
    /// collapsed, otherwise its first instance row.
    fn select_group_first(&mut self, label: &str) {
        let items = self.display_items();
        for (i, it) in items.iter().enumerate() {
            let belongs = match it {
                DisplayItem::Host { label: l } => l == label,
                DisplayItem::Instance { index } => self
                    .services
                    .get(*index)
                    .is_some_and(|s| Self::host_key(&s.hostname) == label),
                DisplayItem::Enum { .. } => label == ENUM_HOST,
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

        // Host headers are not stops; Up/Down lands on instances.
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

    /// Index range of the focused record table inside the combined
    /// [answers, questions] cursor order: Answers covers the raw answers,
    /// Questions the question rows. Services focus is unused by the
    /// record cursor; it spans everything. Anomalies and Hex have no
    /// cursor rows.
    fn detail_range(&self) -> (usize, usize) {
        let (raws, total) = self
            .display_detail()
            .map(|d| {
                (
                    d.ordered_answers().len(),
                    d.ordered_answers().len() + d.questions_len(),
                )
            })
            .unwrap_or((0, 0));
        match self.focus {
            Focus::Answers => (0, raws),
            Focus::Questions => (raws, total),
            Focus::Services => (0, total),
            Focus::Anomalies | Focus::Hex => (0, 0),
        }
    }

    /// Snap the cursor into the newly focused table (first row), keeping
    /// it where it is when already inside.
    fn snap_detail_to_focus(&mut self) {
        self.sync_detail_cursor();
        let before = self.detail_selected;
        let (lo, hi) = self.detail_range();
        if hi > lo && (self.detail_selected < lo || self.detail_selected >= hi) {
            self.detail_selected = lo;
        }
        // New row means new hex bytes: restart the dump at the top and
        // scroll the anomalies pane to the row's finding.
        if self.detail_selected != before {
            self.restart_for_new_row();
        }
        self.detail_anchor = self
            .display_detail()
            .and_then(|d| Self::identity_at_detail(&d, self.detail_selected));
    }

    /// Record cursor over the focused table: raw answers for Answers,
    /// question rows for Questions. The cursor tracks row identity, so
    /// TTL resorting and re-announcements don't yank the selection to
    /// another row.
    fn move_detail_cursor(&mut self, delta: isize) {
        self.sync_detail_cursor();
        // Resuming cursor-follow: manual scroll ends once the cursor moves.
        self.detail_free_scroll = false;
        let before = self.detail_selected;
        let (lo, hi) = self.detail_range();
        if hi <= lo {
            return;
        }
        if self.detail_selected < lo || self.detail_selected >= hi {
            self.detail_selected = if delta < 0 { hi - 1 } else { lo };
        } else if delta > 0 {
            if self.detail_selected + 1 < hi {
                self.detail_selected += 1;
            }
        } else if delta < 0 && self.detail_selected > lo {
            self.detail_selected -= 1;
        }
        self.detail_anchor = self
            .display_detail()
            .and_then(|d| Self::identity_at_detail(&d, self.detail_selected));
        // New row means new hex bytes: restart the dump at the top and
        // scroll the anomalies pane to the row's finding.
        if self.detail_selected != before {
            self.restart_for_new_row();
        }
    }

    /// First/last row of the focused table.
    fn move_detail_edge(&mut self, first: bool) {
        self.sync_detail_cursor();
        self.detail_free_scroll = false;
        let before = self.detail_selected;
        let (lo, hi) = self.detail_range();
        self.detail_selected = if hi <= lo || first { lo } else { hi - 1 };
        self.detail_anchor = self
            .display_detail()
            .and_then(|d| Self::identity_at_detail(&d, self.detail_selected));
        if self.detail_selected != before {
            self.restart_for_new_row();
        }
    }

    /// Page the record cursor by one Answers-table viewport. Falls back
    /// to 10 rows before the first draw answers the real height.
    fn page_detail(&mut self, pages: isize) {
        let per_page = self.record_viewport.get().max(1) as isize;
        let steps = pages * per_page;
        let n = steps.unsigned_abs().min(1000);
        for _ in 0..n {
            let before = self.detail_selected;
            self.move_detail_cursor(steps.signum());
            if self.detail_selected == before {
                break;
            }
        }
    }

    /// Nudge the Answers viewport without moving the record cursor, and pin
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

    /// Scroll the focused detail viewport: the Hex or Anomalies dump
    /// while it holds focus, otherwise the Answers table (which also
    /// scrolls from the Services and Questions panes).
    fn scroll_focused_detail(&mut self, delta: isize) {
        if self.focus == Focus::Hex {
            self.scroll_hex(delta);
        } else if self.focus == Focus::Anomalies {
            self.scroll_anomalies(delta);
        } else {
            self.scroll_detail(delta);
        }
    }

    /// Nudge a cursorless viewport offset, saturating at zero. Upper
    /// clamping happens at render time, where the line count is known.
    /// Shared by the Hex, Anomalies, and metrics panes.
    fn bump_offset(offset: &Cell<usize>, delta: isize) {
        let cur = offset.get();
        let next = if delta < 0 {
            cur.saturating_sub(delta.unsigned_abs())
        } else {
            cur.saturating_add(delta.unsigned_abs())
        };
        offset.set(next);
    }

    /// Page a cursorless viewport by viewportfuls.
    fn page_offset(viewport: &Cell<usize>, pages: isize) -> isize {
        viewport.get().max(1) as isize * pages
    }

    /// Nudge the Hex viewport; the dump follows the record cursor, so
    /// there is no cursor to resume and no pin flag.
    fn scroll_hex(&mut self, delta: isize) {
        Self::bump_offset(&self.hex_offset, delta);
    }

    fn scroll_hex_edge(&mut self, first: bool) {
        if first {
            self.hex_offset.set(0);
        } else {
            self.hex_offset.set(usize::MAX / 2);
        }
    }

    fn page_hex(&mut self, pages: isize) {
        let steps = Self::page_offset(&self.hex_viewport, pages);
        self.scroll_hex(steps);
    }

    /// Nudge the Anomalies viewport; the findings follow the record
    /// cursor, so there is no cursor to resume and no pin flag. Any
    /// manual scroll pauses tracking until the cursor moves again.
    fn scroll_anomalies(&mut self, delta: isize) {
        Self::bump_offset(&self.anomalies_offset, delta);
        self.anomalies_follow.set(false);
    }

    /// New detail row: restart the hex dump at the top and scroll the
    /// Anomalies pane to the row's finding.
    fn restart_for_new_row(&mut self) {
        self.hex_offset.set(0);
        self.hex_selected_field.set(None);
        self.hex_field_hits.borrow_mut().clear();
        self.follow_anomalies_cursor();
    }

    /// Offset the Anomalies pane should take before viewport clamping:
    /// the cursor's finding while tracking, 0 when tracking a list
    /// that lost its match, or the untouched manual offset otherwise.
    /// Pure so the follow/no-follow decision is unit-testable; draw
    /// clamps the result to the viewport.
    pub(crate) fn tracked_anomalies_offset(
        follow: bool,
        current: usize,
        match_idx: Option<usize>,
        total: usize,
    ) -> usize {
        if !follow {
            return current;
        }
        match match_idx {
            Some(at) => at,
            None if current >= total => 0,
            None => current,
        }
    }

    /// Scroll the Anomalies pane to the finding that belongs to the
    /// highlighted row, or to the top when nothing matches, and resume
    /// tracking it: while tracking, a changed finding list re-anchors
    /// the viewport instead of leaving the marker behind. Called on
    /// cursor moves; any manual scroll pauses tracking until the cursor
    /// moves again.
    fn follow_anomalies_cursor(&mut self) {
        let at = self
            .anomalies_for_selected()
            .iter()
            .position(|p| p.cursor_match)
            .unwrap_or(0);
        self.anomalies_offset.set(at);
        self.anomalies_follow.set(true);
    }

    fn scroll_anomalies_edge(&mut self, first: bool) {
        self.anomalies_follow.set(false);
        if first {
            self.anomalies_offset.set(0);
        } else {
            self.anomalies_offset.set(usize::MAX / 2);
        }
    }

    fn page_anomalies(&mut self, pages: isize) {
        let steps = Self::page_offset(&self.anomalies_viewport, pages);
        self.scroll_anomalies(steps);
    }

    /// Scroll the metrics overlay; upper clamping happens at render time.
    fn scroll_metrics(&mut self, delta: isize) {
        Self::bump_offset(&self.metrics_scroll, delta);
    }

    fn scroll_metrics_edge(&mut self, first: bool) {
        if first {
            self.metrics_scroll.set(0);
        } else {
            self.metrics_scroll.set(usize::MAX / 2);
        }
    }

    fn page_metrics(&mut self, pages: isize) {
        let steps = Self::page_offset(&self.metrics_viewport, pages);
        self.scroll_metrics(steps);
    }

    /// Pan the metrics overlay horizontally (chars); upper clamping
    /// happens at render time against the longest value.
    fn scroll_metrics_h(&mut self, delta: isize) {
        Self::bump_offset(&self.metrics_hscroll, delta);
    }

    /// Identity of the table row at an index (raw answers first, then
    /// questions by type/newest-first, matching the rendered table).
    fn identity_at_detail(target: &DetailTarget<'_>, index: usize) -> Option<DetailCursorKey> {
        let raws = target.ordered_answers();
        if index < raws.len() {
            let r = raws[index];
            return Some(DetailCursorKey::Record {
                name: r.name.clone(),
                rtype: r.rtype,
                rdata: r.rdata.clone(),
                source: r.source,
            });
        }
        target
            .ordered_questions()
            .into_iter()
            .nth(index - raws.len())
            .map(|q| DetailCursorKey::Question {
                name: q.0.clone(),
                rtype: q.1.clone(),
                source: q.2,
            })
    }

    /// Index of the row with an identity, if still present.
    fn position_of_detail(target: &DetailTarget<'_>, key: &DetailCursorKey) -> Option<usize> {
        let raws = target.ordered_answers();
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
            } => target
                .ordered_questions()
                .iter()
                .position(|q| q.0 == *name && q.1 == *rtype && q.2 == *source)
                .map(|pos| pos + raws.len()),
        }
    }

    /// Keep the detail cursor pointed at the displayed target, resetting to
    /// the first entry when the target changes (or disappears) and
    /// re-anchoring the index to the tracked identity otherwise. Headers
    /// select nothing, so they leave the cursor (and sticky target) alone.
    fn sync_detail_cursor(&mut self) {
        let svc_key = self
            .selected_service()
            .map(|s| (s.service_type.clone(), s.instance.clone()));
        let enum_key = self.selected_enum().map(|e| e.name.clone());
        if svc_key.is_none() && enum_key.is_none() {
            // Headers show the full unmarked list from the top: no row
            // to track, so a stale manual offset must not linger.
            self.anomalies_offset.set(0);
            self.anomalies_follow.set(false);
            self.hex_selected_field.set(None);
            self.hex_field_hits.borrow_mut().clear();
            return;
        }
        if self.detail_svc_key != svc_key || self.detail_enum_key != enum_key {
            self.detail_svc_key = svc_key;
            self.detail_enum_key = enum_key;
            self.detail_selected = 0;
            self.detail_offset.set(0);
            self.detail_free_scroll = false;
            self.questions_offset.set(0);
            self.restart_for_new_row();
            self.detail_anchor = self
                .display_detail()
                .and_then(|d| Self::identity_at_detail(&d, self.detail_selected));
            return;
        }
        // Re-anchor the index to the tracked identity; rows reshuffle as
        // TTLs tick and re-announcements land.
        let anchor = self.detail_anchor.clone();
        let pos = self.display_detail().and_then(|d| {
            anchor
                .as_ref()
                .and_then(|a| Self::position_of_detail(&d, a))
        });
        match (pos, anchor) {
            (Some(pos), _) => self.detail_selected = pos,
            (None, Some(_)) => {
                // Tracked row expired away (capped question list): park on
                // the last raw record instead of pointing at shifted churn.
                self.hex_selected_field.set(None);
                self.hex_field_hits.borrow_mut().clear();
                let parked = self
                    .display_detail()
                    .map(|d| d.ordered_answers().len().saturating_sub(1))
                    .unwrap_or(0);
                self.detail_selected = parked;
                self.detail_anchor = self
                    .display_detail()
                    .and_then(|d| Self::identity_at_detail(&d, self.detail_selected));
            }
            (None, None) => {}
        }
        // Clamp against entries that aged away (capped question list).
        let max = self
            .display_detail()
            .map(|d| (d.ordered_answers().len() + d.questions_len()).saturating_sub(1))
            .unwrap_or(0);
        if self.detail_selected > max {
            self.detail_selected = max;
        }
    }

    fn ingest_event(&mut self, ev: &browse::Event) {
        log::trace!(
            "mex: ingesting packet from {} ({} answer(s), {} question(s))",
            ev.source,
            ev.answers.len(),
            ev.questions.len()
        );
        for rec in &ev.answers {
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
        if is_enum_name(rec.name.trim_end_matches('.')) {
            if let Some(entry) = self
                .enum_entries
                .iter_mut()
                .find(|e| e.name.eq_ignore_ascii_case(rec.name.trim_end_matches('.')))
            {
                entry.last_seen = Instant::now();
                entry.last_event = Some(ev.clone());
                // DNS names compare case-insensitively (RFC 6763 §7): a
                // peer varying the wire case must refresh the row, not
                // grow the list.
                if let Some(pos) = entry.answers.iter().position(|r| {
                    r.name.eq_ignore_ascii_case(&rec.name)
                        && r.rtype == rec.rtype
                        && same_ptr_target(r, rec)
                        && r.source == rec.source
                }) {
                    entry.answers[pos] = rec.clone();
                } else {
                    entry.answers.push(rec.clone());
                }
            }
            return;
        }
        let mut names = vec![rec.name.trim_end_matches('.').to_lowercase()];
        if rec.rtype == 12 {
            names.push(rec.rdata.trim_end_matches('.').to_lowercase());
        }
        // One hostname backs many services: file the goodbye on every
        // match (notably TTL 0 A/AAAA) instead of stopping at the first.
        let mut hits = Vec::new();
        for (i, svc) in self.services.iter().enumerate() {
            let full = format!("{}.{}", svc.instance, svc.service_type).to_lowercase();
            let host = svc.hostname.trim_end_matches('.').to_lowercase();
            let inst = svc.instance.to_lowercase();
            let alternate = svc.answers.iter().any(|r| {
                if r.rtype != 33 {
                    return false;
                }
                if r.ttl <= r.received_at.elapsed().as_secs() as u32 {
                    return false;
                }
                let target = r
                    .rdata
                    .splitn(4, ' ')
                    .nth(3)
                    .unwrap_or("")
                    .trim()
                    .trim_end_matches('.')
                    .to_lowercase();
                names.contains(&target)
            });
            if names.iter().any(|n| *n == full || *n == host || *n == inst) || alternate {
                hits.push(i);
            }
        }
        for i in hits {
            self.services[i].last_event = Some(ev.clone());
            self.push_record(i, rec);
        }
    }

    /// File a question asking for a service, so the Records view can show
    /// who is asking (and the hex pane can show the query packet).
    /// Enumeration questions file on their selectable enumeration row.
    fn route_question(&mut self, q: &browse::RawRecord, ev: &browse::Event) {
        self.note_observed(q, ev);
        let name = q.name.trim_end_matches('.').to_lowercase();
        if is_enum_name(&name) {
            for entry in &mut self.enum_entries {
                if entry.name.to_lowercase() == name {
                    Self::file_question_counted(
                        &mut entry.questions,
                        &mut entry.questions_dropped,
                        q.name.clone(),
                        q.rtype_str.clone(),
                        ev.source,
                        q.received_at,
                        ev.raw_bytes.clone(),
                    );
                    entry.last_seen = Instant::now();
                    entry.last_event = Some(ev.clone());
                }
            }
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
                let svc = &mut self.services[i];
                Self::file_question_counted(
                    &mut svc.questions,
                    &mut svc.questions_dropped,
                    q.name.clone(),
                    q.rtype_str.clone(),
                    ev.source,
                    q.received_at,
                    ev.raw_bytes.clone(),
                );
            }
        }
    }

    /// File one question row, refreshing the timestamp when the same
    /// (name, type, source) asks again. Caps the list at 10 rows.
    /// Returns true when an old row was evicted, so callers can count
    /// drops for the dump truncation marker.
    ///
    /// Prefer `file_question_counted` at call sites: it files the row
    /// and bumps the entry's eviction counter in one call.
    fn file_question_counted(
        rows: &mut Vec<QuestionRow>,
        drops: &mut u64,
        name: String,
        rtype_str: String,
        source: std::net::SocketAddr,
        at: Instant,
        bytes: Vec<u8>,
    ) {
        if Self::file_question_row(rows, name, rtype_str, source, at, bytes) {
            *drops += 1;
        }
    }

    /// Short label for the record types we ever transmit (the only ones
    /// `route_own_question` can see).
    fn file_question_row(
        rows: &mut Vec<QuestionRow>,
        name: String,
        rtype_str: String,
        source: std::net::SocketAddr,
        at: Instant,
        bytes: Vec<u8>,
    ) -> bool {
        match rows
            .iter()
            .position(|(n, t, src, _, _)| n == &name && t == &rtype_str && src == &source)
        {
            Some(pos) => {
                rows[pos] = (name, rtype_str, source, at, bytes);
                false
            }
            None => {
                rows.push((name, rtype_str, source, at, bytes));
                if rows.len() > 10 {
                    rows.remove(0);
                    true
                } else {
                    false
                }
            }
        }
    }

    /// Short label for the record types we ever transmit (the only ones
    /// `route_own_question` can see).
    fn own_rtype_label(rtype: u16) -> Option<&'static str> {
        match rtype {
            12 => Some("PTR"),
            33 => Some("SRV"),
            16 => Some("TXT"),
            1 => Some("A"),
            28 => Some("AAAA"),
            _ => None,
        }
    }

    /// File a question we sent ourselves, inferred from the send path:
    /// multicast loop is disabled so our transmissions never arrive as
    /// events. Store a minimal query packet for the question fields rather
    /// than reusing unrelated latest-event bytes. Filed for real sends and
    /// §7.3 suppressions alike: both are browse demand. Discovery sends
    /// precede the service, so matching pending instances park them until
    /// `handle_srv` moves them over on promotion. Passive mode sends nothing.
    fn route_own_question(&mut self, name: &str, rtype: u16, qu: bool) {
        let display = name.trim_end_matches('.').to_string();
        let key = display.to_lowercase();
        let Some(label) = Self::own_rtype_label(rtype) else {
            return;
        };
        let bytes = browse::inferred_question_packet(name, rtype, qu).unwrap_or_else(|| {
            log::warn!("mex: cannot encode inferred query packet for {name} TYPE{rtype}");
            Vec::new()
        });
        let at = Instant::now();
        if is_enum_name(&key) {
            for entry in &mut self.enum_entries {
                if entry.name.to_lowercase() == key {
                    Self::file_question_counted(
                        &mut entry.questions,
                        &mut entry.questions_dropped,
                        display.clone(),
                        label.to_string(),
                        SELF_SOURCE,
                        at,
                        bytes.clone(),
                    );
                    entry.last_seen = at;
                }
            }
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
            if full == key || host == key || self.services[i].service_type.to_lowercase() == key {
                let svc = &mut self.services[i];
                Self::file_question_counted(
                    &mut svc.questions,
                    &mut svc.questions_dropped,
                    display.clone(),
                    label.to_string(),
                    SELF_SOURCE,
                    at,
                    bytes.clone(),
                );
            }
        }
        for p in &mut self.pending_instances {
            let full = format!("{}.{}", p.instance, p.service_type).to_lowercase();
            if full == key || p.service_type.to_lowercase() == key {
                Self::file_question_counted(
                    &mut p.questions,
                    &mut p.questions_dropped,
                    display.clone(),
                    label.to_string(),
                    SELF_SOURCE,
                    at,
                    bytes.clone(),
                );
            }
        }
    }

    fn ingest_record(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        log::trace!(
            "mex: ingesting {} record {} from {}",
            rec.rtype_str,
            rec.name,
            ev.source
        );
        match rec.rtype {
            12 => self.handle_ptr(rec, ev),
            33 => self.handle_srv(rec, ev),
            16 => self.handle_txt(rec, ev),
            1 | 28 => self.handle_addr(rec, ev),
            _ => self.handle_other(rec, ev),
        }
    }

    fn handle_ptr(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let st = rec.name.trim_end_matches('.');
        let target = rec.rdata.trim_end_matches('.');

        if is_enum_name(st) {
            // Track enumeration answers for known-answer suppression and
            // for the continuous browse set; polling itself runs through
            // the §5.2 backoff in poll_continuous. Keys are lowercased so
            // `_HTTP` and `_http` announcements coalesce (RFC 6763 §7).
            // The full answer is also filed on the selectable enumeration
            // row so the Answers pane shows what each link advertises.
            self.known_types.insert(target.to_lowercase());
            let enum_key = target.to_lowercase();
            if rec.ttl > 0 {
                self.enum_known
                    .insert(enum_key, (rec.ttl, rec.received_at, rec.iface.clone()));
            } else {
                self.enum_known.remove(&enum_key);
            }
            if let Some(entry) = self
                .enum_entries
                .iter_mut()
                .find(|e| e.name.eq_ignore_ascii_case(st))
            {
                entry.last_seen = Instant::now();
                entry.last_event = Some(ev.clone());
                // DNS names compare case-insensitively (RFC 6763 §7): a
                // peer varying the wire case must refresh the row, not
                // grow the list.
                if let Some(pos) = entry.answers.iter().position(|r| {
                    r.name.eq_ignore_ascii_case(&rec.name)
                        && r.rtype == rec.rtype
                        && same_ptr_target(r, rec)
                        && r.source == rec.source
                }) {
                    entry.answers[pos] = rec.clone();
                } else {
                    entry.answers.push(rec.clone());
                }
                // A fresh answer resets the requery schedule unless a
                // sibling row is still inside its 80%-TTL window.
                let key = (rec.name.trim_end_matches('.').to_string(), rec.rtype);
                let still_expiring = entry.answers.iter().any(|r| {
                    if r.ttl == 0
                        || r.name.trim_end_matches('.') != key.0.as_str()
                        || r.rtype != key.1
                    {
                        return false;
                    }
                    let elapsed = r.received_at.elapsed().as_secs() as u32;
                    elapsed <= r.ttl && elapsed * 5 >= r.ttl * 4
                });
                if !still_expiring {
                    self.requeries.remove(&key);
                }
            }
            return;
        }

        // Reverse-mapping PTRs (in-addr.arpa / ip6.arpa) map addresses to
        // hostnames; they are not service enumeration and must not seed
        // pending services (which check_type_format would then flag).
        if crate::anomalies::is_reverse_ptr(st) {
            return;
        }

        if let Some((subtype, svc_type)) = subtype_owner_parts(rec) {
            let instance = Self::strip_suffix_ci(target, &svc_type).unwrap_or(target);
            // Late subtype PTRs (arriving after the SRV already promoted
            // the service, the normal passive-mode order) land on the live
            // service directly; otherwise they wait in pending for the SRV
            // merge. Touching pending when the service exists strands a
            // duplicate entry that only expires via the grace timeout.
            if let Some(idx) = self.services.iter().position(|s| {
                s.instance.eq_ignore_ascii_case(instance)
                    && s.service_type.eq_ignore_ascii_case(&svc_type)
            }) {
                if !self.services[idx]
                    .subtypes
                    .iter()
                    .any(|s| s.as_slice().eq_ignore_ascii_case(&subtype))
                {
                    self.services[idx].subtypes.push(subtype);
                }
                self.services[idx].last_event = Some(ev.clone());
                self.push_record(idx, rec);
                return;
            }
            let pi = self.ensure_pending(instance, &svc_type);
            if !self.pending_instances[pi]
                .subtypes
                .iter()
                .any(|s| s.as_slice().eq_ignore_ascii_case(&subtype))
            {
                self.pending_instances[pi].subtypes.push(subtype);
            }
            self.pending_instances[pi].answers.push(rec.clone());
            return;
        }

        let instance = Self::strip_suffix_ci(target, st).unwrap_or(target);
        let pi = self.ensure_pending(instance, st);
        self.pending_instances[pi].answers.push(rec.clone());
        // A live PTR for an already-confirmed service must reactivate it
        // here: after a goodbye the service is inactive, and without this
        // forward the PTR would sit in pending until (and unless) a fresh
        // SRV arrives, leaving a returned service stuck offline.
        // push_record only reactivates on live PTR, so SRV/TXT answers
        // still cannot resurrect a withdrawn service.
        if let Some(idx) = self.services.iter().position(|s| {
            s.instance.eq_ignore_ascii_case(instance) && s.service_type.eq_ignore_ascii_case(st)
        }) {
            self.services[idx].last_event = Some(ev.clone());
            self.push_record(idx, rec);
        }
    }

    /// Split a full instance name ("inst._svc._tcp.local") into (instance,
    /// service type). Instance names may legally contain dots (e.g. Fire TV
    /// style "amzn.dmgr:...:..."), so splitting on the first dot misparses
    /// them. Match against known service types instead (longest suffix
    /// wins, case-insensitively per RFC 6763 §7); the caller falls back to
    /// the naive split when nothing is known yet. Both parts keep wire
    /// case; callers compare case-insensitively.
    fn split_instance_type(&self, full_name: &str) -> Option<(String, String)> {
        let mut best: Option<(String, String)> = None;
        let mut consider = |known: &str| {
            if known.is_empty() {
                return;
            }
            if full_name.len() <= known.len() {
                return;
            }
            // Instance names may hold multi-byte UTF-8 (RFC 6763 §4.1.1):
            // skip offsets landing inside a character instead of panicking
            // in `split_at` (e.g. `é._ssh._tcp.local` vs `_https._tcp.local`).
            let off = full_name.len() - known.len();
            if !full_name.is_char_boundary(off) {
                return;
            }
            let (prefix, tail) = full_name.split_at(off);
            if !tail.eq_ignore_ascii_case(known) {
                return;
            }
            let Some(instance) = prefix.strip_suffix('.') else {
                return;
            };
            if instance.is_empty() {
                return;
            }
            let replace = match &best {
                Some((_, current)) => known.len() > current.len(),
                None => true,
            };
            if replace {
                best = Some((instance.to_string(), tail.to_string()));
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
            let new_host = rec
                .rdata
                .splitn(4, ' ')
                .nth(3)
                .unwrap_or("")
                .trim()
                .to_string();
            // Keep a host name stable when several SRVs for the same
            // instance advertise different targets (e.g. a device reachable
            // under both a `.local` and a unicast name): once both targets
            // are known, a refresh of either must not flip the host grouping
            // back and forth. A genuinely new target (one never seen before
            // for this instance) still moves the service, and an expired
            // current host gives way to whatever is live.
            let current_host = self.services[idx].hostname.clone();
            let current_norm = current_host.trim_end_matches('.').to_lowercase();
            let new_norm = new_host.trim_end_matches('.').to_lowercase();
            let update = if current_host.is_empty() || current_norm == new_norm {
                true
            } else {
                let current_live = self.services[idx].answers.iter().any(|r| {
                    if r.rtype != 33 {
                        return false;
                    }
                    let target = r
                        .rdata
                        .splitn(4, ' ')
                        .nth(3)
                        .unwrap_or("")
                        .trim()
                        .trim_end_matches('.')
                        .to_lowercase();
                    target == current_norm && r.ttl > r.received_at.elapsed().as_secs() as u32
                });
                let target_known = self.services[idx].answers.iter().any(|r| {
                    if r.rtype != 33 {
                        return false;
                    }
                    let target = r
                        .rdata
                        .splitn(4, ' ')
                        .nth(3)
                        .unwrap_or("")
                        .trim()
                        .trim_end_matches('.')
                        .to_lowercase();
                    target == new_norm && r.ttl > r.received_at.elapsed().as_secs() as u32
                });
                !current_live || !target_known
            };
            if update {
                self.services[idx].port = sv[2].parse().unwrap_or(0);
                self.services[idx].hostname = new_host;
            }
        }
        self.push_record(idx, rec);
        self.services[idx].last_event = Some(ev.clone());
        // A service promoted after its host's address arrived would miss
        // it until the next announcement (several SRVs, one host):
        // backfill live A/AAAA rows already held by siblings. Cloning is
        // idempotent (push_record dedups by name/type/rdata/source) and
        // keeps the original receipt time, so TTL aging stays consistent.
        let host_key = self.services[idx]
            .hostname
            .trim_end_matches('.')
            .to_lowercase();
        if !host_key.is_empty() {
            let mut backfill = Vec::new();
            for (si, svc) in self.services.iter().enumerate() {
                if si == idx {
                    continue;
                }
                if svc.hostname.trim_end_matches('.').to_lowercase() != host_key {
                    continue;
                }
                for r in &svc.answers {
                    // Owner check, not just sibling check: a sibling that
                    // moved SRV targets keeps its old-host rows, and those
                    // must not leak onto this host. Names compare
                    // case-insensitively (RFC 6763 §7).
                    if (r.rtype == 1 || r.rtype == 28)
                        && r.name.trim_end_matches('.').to_lowercase() == host_key
                        && r.ttl > r.received_at.elapsed().as_secs() as u32
                    {
                        backfill.push(r.clone());
                    }
                }
            }
            for r in &backfill {
                self.push_record(idx, r);
            }
        }

        // merge any cached data from pending_instances, routing each
        // record through push_record so live PTRs reactivate a returned
        // service (and replace their goodbye rows) instead of duplicating
        // them via a blind extend.
        let svc_idx = idx;
        let mut i = 0;
        while i < self.pending_instances.len() {
            if self.pending_instances[i]
                .instance
                .eq_ignore_ascii_case(&instance)
                && self.pending_instances[i]
                    .service_type
                    .eq_ignore_ascii_case(&service_type)
            {
                let p = self.pending_instances.swap_remove(i);
                for sub in p.subtypes {
                    if !self.services[svc_idx]
                        .subtypes
                        .iter()
                        .any(|s| s.as_slice().eq_ignore_ascii_case(&sub))
                    {
                        self.services[svc_idx].subtypes.push(sub);
                    }
                }
                for q in p.questions {
                    let svc = &mut self.services[svc_idx];
                    Self::file_question_counted(
                        &mut svc.questions,
                        &mut svc.questions_dropped,
                        q.0,
                        q.1,
                        q.2,
                        q.3,
                        q.4,
                    );
                }
                // Evicted pending rows never reappear: carry the count so
                // the dump still marks the promoted list as truncated.
                self.services[svc_idx].questions_dropped += p.questions_dropped;
                self.services[svc_idx].last_seen =
                    self.services[svc_idx].last_seen.max(p.last_seen);
                let answers = p.answers;
                for rec in &answers {
                    self.push_record(svc_idx, rec);
                }
            } else {
                i += 1;
            }
        }
    }

    fn handle_txt(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
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
        // Late TXT (arriving after the SRV already promoted the service,
        // the normal passive-mode order) lands on the live service
        // directly; otherwise it waits in pending for the SRV merge.
        if let Some(idx) = self.services.iter().position(|s| {
            s.instance.eq_ignore_ascii_case(&instance)
                && s.service_type.eq_ignore_ascii_case(&service_type)
        }) {
            self.services[idx].last_event = Some(ev.clone());
            self.push_record(idx, rec);
            return;
        }
        let pi = self.ensure_pending(&instance, &service_type);

        self.pending_instances[pi].answers.push(rec.clone());
    }

    fn handle_addr(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let host = rec.name.trim_end_matches('.').to_lowercase();
        // One hostname backs many services (several SRVs, one host):
        // file on every match, not just the first. A service may also be
        // reachable under alternate SRV targets, so route addresses for any
        // live target of the service, not only the selected hostname.
        let mut hits = Vec::new();
        for (i, svc) in self.services.iter().enumerate() {
            let selected = svc.hostname.trim_end_matches('.').to_lowercase() == host;
            let alternate = svc.answers.iter().any(|r| {
                r.rtype == 33
                    && r.ttl > r.received_at.elapsed().as_secs() as u32
                    && srv_target(&r.rdata).is_some_and(|target| target.eq_ignore_ascii_case(&host))
            });
            if selected || alternate {
                hits.push(i);
            }
        }
        if hits.is_empty() {
            let records = self.pending_addrs.entry(host).or_default();
            if let Some(pending) = records.iter_mut().find(|pending| {
                pending.rtype == rec.rtype
                    && pending.rdata == rec.rdata
                    && pending.source == rec.source
            }) {
                *pending = rec.clone();
            } else {
                records.push(rec.clone());
            }
            return;
        }
        for i in hits {
            self.services[i].last_event = Some(ev.clone());
            self.push_record(i, rec);
        }
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
            if p.instance.eq_ignore_ascii_case(instance)
                && p.service_type.eq_ignore_ascii_case(service_type)
            {
                self.pending_instances[i].last_seen = Instant::now();
                return i;
            }
        }
        let i = self.pending_instances.len();
        self.pending_instances.push(PendingService {
            instance: instance.to_string(),
            service_type: service_type.to_string(),
            answers: Vec::new(),
            subtypes: Vec::new(),
            questions: Vec::new(),
            questions_dropped: 0,
            last_seen: Instant::now(),
        });
        i
    }

    fn ensure_svc(&mut self, instance: &str, service_type: &str) -> usize {
        let now = Instant::now();
        for (i, s) in self.services.iter().enumerate() {
            if s.instance.eq_ignore_ascii_case(instance)
                && s.service_type.eq_ignore_ascii_case(service_type)
            {
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
            answers: Vec::new(),
            questions: Vec::new(),
            questions_dropped: 0,
            last_seen: now,
            is_active: true,
            last_event: None,
        });
        self.metrics.services_seen_total += 1;
        self.services.len() - 1
    }

    fn push_record(&mut self, svc_idx: usize, rec: &browse::RawRecord) {
        let s = &mut self.services[svc_idx];
        // Host addresses are not signs of service life: filing one on an
        // already-withdrawn service must not extend its grace deadline.
        // Only live PTRs reactivate, so an address never clears `withdrawn`.
        let withdrawn = !s.is_active;
        let prev_seen = s.last_seen;
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
        if let Some(pos) = s.answers.iter().position(|r| {
            r.name == rec.name
                && r.rtype == rec.rtype
                && r.rdata == rec.rdata
                && r.source == rec.source
        }) {
            s.answers[pos] = rec.clone();
        } else {
            s.answers.push(rec.clone());
        }
        // Fresh answer resets the RFC 6762 §5.2 requery schedule, but only
        // if no row for this key is still inside the 80%-TTL window:
        // sibling rows with other rdata/sources may still need their
        // backoff, and clearing on every unrelated answer re-arms the
        // trigger each loop iteration (reset-driven storm).
        if rec.ttl > 0 {
            let key = (rec.name.trim_end_matches('.').to_string(), rec.rtype);
            let still_expiring = self.services[svc_idx].answers.iter().any(|r| {
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
        if withdrawn && (rec.rtype == 1 || rec.rtype == 28) {
            // Addresses never reactivate, so a withdrawn service is still
            // withdrawn here: keep its original grace deadline.
            self.services[svc_idx].last_seen = prev_seen;
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
            if !svc.is_active || svc.answers.is_empty() {
                continue;
            }
            let has_ptr = svc.answers.iter().any(|r| r.rtype == 12);
            let gone = if has_ptr {
                !svc.answers.iter().any(|r| r.rtype == 12 && is_live(r))
            } else {
                !svc.answers.iter().any(is_live)
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
        if now >= self.next_pending_addr_prune {
            self.next_pending_addr_prune = now + PENDING_ADDR_PRUNE_INTERVAL;
            self.pending_addrs.retain(|_, records| {
                records.retain(|r| r.ttl > 0 && r.ttl > r.received_at.elapsed().as_secs() as u32);
                !records.is_empty()
            });
        }
        Self::expire_stale_services(&mut self.services);
        let before = self.services.len();
        self.services
            .retain(|s| s.is_active || now.duration_since(s.last_seen) < grace);
        self.metrics.services_expired_total += (before - self.services.len()) as u64;
        self.pending_instances
            .retain(|p| now.duration_since(p.last_seen) < grace);
        // Drop schedules for names that no longer exist, so dead services
        // stop costing even an hourly query (RFC 6762 §5.2: no maintenance
        // without active interest). Names are normalized to lowercase so
        // `_HTTP` and `_http` share one set entry (RFC 6763 §7) and the
        // retains below stay O(1) `contains` lookups.
        let mut live: HashSet<(String, u16)> = HashSet::new();
        live.insert((ENUM_SERVICE.to_string(), 12));
        for entry in &self.enum_entries {
            live.insert((entry.name.to_lowercase(), 12));
            for rec in &entry.answers {
                live.insert((rec.name.trim_end_matches('.').to_lowercase(), rec.rtype));
            }
        }
        for svc in &self.services {
            live.insert((svc.service_type.to_lowercase(), 12));
            let full = format!("{}.{}", svc.instance, svc.service_type).to_lowercase();
            live.insert((full.clone(), 33));
            live.insert((full, 16));
            if !svc.hostname.is_empty() {
                let host = svc.hostname.trim_end_matches('.').to_lowercase();
                live.insert((host.clone(), 1));
                live.insert((host, 28));
            }
            for rec in &svc.answers {
                live.insert((rec.name.trim_end_matches('.').to_lowercase(), rec.rtype));
            }
        }
        for p in &self.pending_instances {
            live.insert((p.service_type.to_lowercase(), 12));
            let full = format!("{}.{}", p.instance, p.service_type).to_lowercase();
            live.insert((full.clone(), 33));
            live.insert((full, 16));
        }
        for t in self.enum_known.keys() {
            live.insert((t.clone(), 12));
        }
        self.requeries
            .retain(|k, _| live.contains(&(k.0.to_lowercase(), k.1)));
        self.continuous.retain(|k, _| live.contains(k));
        // Provenance outlives short schedule gaps but not dead
        // interests: keep entries with a live schedule key or a recent
        // event, so a recently expired interest still reports its
        // terminal state in dumps.
        self.query_history.retain(|k, v| {
            live.contains(k)
                || [
                    v.transmitted,
                    v.suppressed,
                    v.observed.as_ref().map(|o| o.at),
                ]
                .into_iter()
                .flatten()
                .any(|t| t.elapsed() < INTEREST_GRACE)
        });
        // Overheard QM queries are single-use and short-lived (§7.3).
        self.overheard
            .retain(|_, (seen, _, _)| seen.elapsed() < OVERHEARD_WINDOW);
        // Drop TXT expansion state for answers that no longer exist.
        let mut live_txt = HashSet::new();
        for svc in &self.services {
            for rec in &svc.answers {
                if rec.rtype == 16 {
                    live_txt.insert(Self::txt_key(rec));
                }
            }
        }
        for entry in &self.enum_entries {
            for rec in &entry.answers {
                if rec.rtype == 16 {
                    live_txt.insert(Self::txt_key(rec));
                }
            }
            // Enumeration rows are persistent; prune only rows long past
            // their TTL so the Answers pane stays bounded.
        }
        self.expanded_txt.retain(|k| live_txt.contains(k));
        for entry in &mut self.enum_entries {
            entry
                .answers
                .retain(|r| r.received_at.elapsed().as_secs() as u32 <= r.ttl.saturating_add(120));
            entry.questions.retain(|_| true);
        }
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
        // Collapsed headers stay put so their host can be unfolded again.
        if matches!(
            self.display_items().get(self.selected_display),
            Some(DisplayItem::Host { label }) if !self.is_host_collapsed(label)
        ) {
            self.move_selection(1);
        }
        if matches!(
            self.display_items().get(self.selected_display),
            Some(DisplayItem::Host { label }) if !self.is_host_collapsed(label)
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
        // selected target to keep the right panes alive while navigating.
        // Selecting one kind clears the other, so a header never
        // resurrects a stale target of the other kind.
        if let Some(key) = self
            .selected_service()
            .map(|s| (s.service_type.clone(), s.instance.clone()))
        {
            self.sticky_key = Some(key);
            self.sticky_enum_key = None;
        }
        if let Some(enum_key) = self.selected_enum().map(|e| e.name.clone()) {
            self.sticky_enum_key = Some(enum_key);
            self.sticky_key = None;
        }
        self.sync_detail_cursor();
    }

    pub fn is_host_collapsed(&self, label: &str) -> bool {
        self.collapsed_hosts.contains(label)
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

    /// Collapsed by default: only answers explicitly expanded via `Enter`
    /// show their child rows.
    pub fn is_txt_expanded(&self, rec: &browse::RawRecord) -> bool {
        self.expanded_txt.contains(&Self::txt_key(rec))
    }

    /// Toggle the TXT record under the Tab cursor. Returns false when the
    /// cursor is not on an expandable TXT row (caller falls back to the
    /// host fold). Headers select nothing, so `Enter` on a header
    /// keeps folding the host instead of touching TXT state.
    fn toggle_txt_expanded(&mut self) -> bool {
        if self.selected_service().is_none() && self.selected_enum().is_none() {
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

    pub fn selected_service(&self) -> Option<&ServiceEntry> {
        let items = self.display_items();
        match items.get(self.selected_display)? {
            DisplayItem::Instance { index } => self.services.get(*index),
            _ => None,
        }
    }

    pub fn selected_enum(&self) -> Option<&EnumEntry> {
        let items = self.display_items();
        match items.get(self.selected_display)? {
            DisplayItem::Enum { index } => self.enum_entries.get(*index),
            _ => None,
        }
    }

    pub fn latest_event_for_selected(&self) -> Option<&browse::Event> {
        // Newest record first, then the target's last-seen packet: the
        // shared buffer ages with total traffic, so a quiet target's
        // packets may all be gone while its answers live on.
        let target = self.display_detail()?;
        for rec in target.all_answers().iter().rev() {
            if let Some(ev) = self
                .raw_events
                .iter()
                .rev()
                .find(|ev| ev.source == rec.source)
            {
                return Some(ev);
            }
        }
        target.last_event()
    }

    /// Service shown in the right panes: the selected one, or the last
    /// selected one while the cursor sits on a service-type header.
    /// Kept for tests; the panes render through `display_detail`.
    #[cfg(test)]
    pub fn display_service(&self) -> Option<&ServiceEntry> {
        if let Some(svc) = self.selected_service() {
            return Some(svc);
        }
        let key = self.sticky_key.as_ref()?;
        self.services
            .iter()
            .find(|s| s.service_type == key.0 && s.instance == key.1)
    }

    /// Right-pane target: the selected service or enumeration row, or the
    /// last selected one while the cursor sits on a header.
    pub fn display_detail(&self) -> Option<DetailTarget<'_>> {
        if let Some(svc) = self.selected_service() {
            return Some(DetailTarget::Service(svc));
        }
        if let Some(entry) = self.selected_enum() {
            return Some(DetailTarget::Enum(entry));
        }
        if let Some(key) = self.sticky_key.as_ref() {
            if let Some(svc) = self
                .services
                .iter()
                .find(|s| s.service_type == key.0 && s.instance == key.1)
            {
                return Some(DetailTarget::Service(svc));
            }
        }
        if let Some(key) = self.sticky_enum_key.as_ref() {
            if let Some(entry) = self.enum_entries.iter().find(|e| &e.name == key) {
                return Some(DetailTarget::Enum(entry));
            }
        }
        None
    }

    /// Entry under the Tab cursor in the Records table: a raw record row or
    /// a question row (table order is raw answers first, then questions
    /// by type/newest-first, matching the rendered table).
    pub fn selected_detail_entry(&self) -> Option<DetailEntry<'_>> {
        let target = self.display_detail()?;
        match &target {
            DetailTarget::Service(svc) => {
                let key = (svc.service_type.clone(), svc.instance.clone());
                if self.detail_svc_key.as_ref() != Some(&key) {
                    return None;
                }
            }
            DetailTarget::Enum(entry) => {
                if self.detail_enum_key.as_ref() != Some(&entry.name) {
                    return None;
                }
            }
        }
        let raws = target.ordered_answers();
        if self.detail_selected < raws.len() {
            return Some(DetailEntry::Record(raws[self.detail_selected]));
        }
        target
            .ordered_questions()
            .into_iter()
            .nth(self.detail_selected - raws.len())
            .map(|q| DetailEntry::Question {
                name: &q.0,
                rtype_str: &q.1,
                raw: &q.4,
                source: &q.2,
            })
    }

    /// Whether the left selection rests on a header instead of a service
    /// row, so the Anomalies pane shows service-level findings for the
    /// sticky target rather than row findings.
    pub fn anomalies_show_service_level(&self) -> bool {
        self.display_detail().is_some()
            && self.selected_service().is_none()
            && self.selected_enum().is_none()
    }

    /// Current scope of the Anomalies pane: the highlighted record or
    /// question row, the displayed target while resting on a header, or
    /// nothing at all.
    pub fn anomaly_scope(&self) -> AnomalyScope<'_> {
        if self.anomalies_show_service_level() {
            if let Some(target) = self.display_detail() {
                return AnomalyScope::ServiceLevel(target);
            }
            return AnomalyScope::None;
        }
        match self.selected_detail_entry() {
            Some(DetailEntry::Record(rec)) => AnomalyScope::Record(rec),
            Some(DetailEntry::Question {
                name,
                rtype_str,
                source,
                ..
            }) => AnomalyScope::Question(QuestionKey {
                name,
                rtype_str,
                source,
            }),
            None => AnomalyScope::None,
        }
    }

    /// Every surfaced finding for the displayed service, each flagged
    /// when it belongs to the highlighted detail row. A gone record row
    /// (expired or goodbye) yields nothing: the pane names the gone
    /// state instead of any list.
    pub fn anomalies_for_selected(&self) -> Vec<PaneAnomaly> {
        if let Some(DetailEntry::Record(rec)) = self.selected_detail_entry() {
            if record_liveness(rec) != RecordLiveness::Live {
                return Vec::new();
            }
        }
        let scope = self.anomaly_scope();
        let id = match &scope {
            AnomalyScope::ServiceLevel(target) => Self::detail_service_id(target),
            AnomalyScope::Record(_) | AnomalyScope::Question(_) => {
                let Some(target) = self.display_detail() else {
                    return Vec::new();
                };
                Self::detail_service_id(&target)
            }
            AnomalyScope::None => return Vec::new(),
        };
        let found = self.anomalies();
        let row: Vec<anomalies::Anomaly> = match scope {
            AnomalyScope::Record(rec) => Self::record_anomalies_in(&found, rec, &id),
            AnomalyScope::Question(key) => Self::question_anomalies_in(&found, key, &id),
            _ => Vec::new(),
        };
        found
            .into_iter()
            .filter(|a| a.service == id && a.is_surfaced())
            .map(|a| {
                let cursor_match = row.contains(&a);
                PaneAnomaly {
                    anomaly: a,
                    cursor_match,
                }
            })
            .collect()
    }

    /// Service id owning a detail target, matching `Anomaly.service`.
    fn detail_service_id(target: &DetailTarget<'_>) -> String {
        match target {
            DetailTarget::Service(s) => anomalies::service_id(&s.instance, &s.service_type),
            DetailTarget::Enum(_) => anomalies::ENUMERATION_SERVICE.to_string(),
        }
    }

    /// Row-identity match for one observed question row within a
    /// precomputed finding set: the demand-side leak attributed to its
    /// querier. Own inferred sends (`SELF_SOURCE`, port 0) never match a
    /// finding, and unrecognised type labels stay quiet.
    fn question_anomalies_in(
        found: &[anomalies::Anomaly],
        key: QuestionKey<'_>,
        id: &str,
    ) -> Vec<anomalies::Anomaly> {
        let Some(rtype) = anomalies::rtype_from_str(key.rtype_str) else {
            return Vec::new();
        };
        let name = key.name.trim_end_matches('.').to_lowercase();
        let src = key.source.to_string();
        found
            .iter()
            .filter(|a| a.kind.is_question())
            .filter(|a| a.is_surfaced())
            .filter(|a| a.service == id)
            .filter(|a| a.rtype == Some(rtype))
            .filter(|a| {
                a.record_name
                    .as_ref()
                    .is_some_and(|n| n.trim_end_matches('.').to_lowercase() == name)
            })
            .filter(|a| a.source.as_deref() == Some(src.as_str()))
            .cloned()
            .collect()
    }

    /// Row-identity match for the highlighted record row within a
    /// precomputed finding set: findings whose (name, type, rdata)
    /// identity matches and whose service owns the displayed target,
    /// including spanning `ttl-unstable` findings matched by (name, type).
    fn record_anomalies_in(
        found: &[anomalies::Anomaly],
        rec: &browse::RawRecord,
        id: &str,
    ) -> Vec<anomalies::Anomaly> {
        let name = rec.name.trim_end_matches('.').to_lowercase();
        let rdata_key = anomalies::anomaly_match_key(rec.rtype, &rec.rdata);
        found
            .iter()
            .filter(|a| a.service == id)
            .filter(|a| a.is_surfaced())
            .filter(|a| a.rtype == Some(rec.rtype))
            .filter(|a| {
                a.record_name
                    .as_ref()
                    .is_some_and(|n| n.trim_end_matches('.').to_lowercase() == name)
            })
            .filter(|a| match a.rdata.as_ref() {
                Some(rdata) => anomalies::anomaly_match_key(rec.rtype, rdata) == rdata_key,
                // Spanning `ttl-unstable` findings carry no rdata: they
                // match every row of the same name and type. Narrowed to
                // that kind on purpose — a future rdata-less finding of
                // another kind must not silently span rows.
                None => a.kind == anomalies::AnomalyKind::TtlUnstable,
            })
            .cloned()
            .collect()
    }

    /// Field ranges for the selected record or uniquely matched query question.
    pub fn selected_detail_fields(&self) -> Option<Vec<browse::RecordField>> {
        match self.selected_detail_entry()? {
            DetailEntry::Record(record) => Some(browse::record_fields(&record.wire, record.rtype)),
            DetailEntry::Question {
                name,
                rtype_str,
                raw,
                ..
            } if !raw.is_empty() => browse::question_fields(raw, name, rtype_str),
            DetailEntry::Question { .. } => None,
        }
    }

    /// Hex dump payload: selected record bytes or the stored query packet.
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
                source,
            } => {
                let title = format!(" QRY {rtype_str} {name} ");
                if *source == SELF_SOURCE {
                    return Some((raw.to_vec(), format!("{title}(inferred) ")));
                }
                if raw.is_empty() {
                    let fallback = self
                        .latest_event_for_selected()
                        .map(|ev| ev.raw_bytes.clone())
                        .unwrap_or_default();
                    return Some((fallback, format!("{title}(raw packet) ")));
                }
                Some((raw.to_vec(), title))
            }
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
            owner_labels: name
                .trim_end_matches('.')
                .split('.')
                .map(|label| label.as_bytes().to_vec())
                .collect(),
            ptr_target_labels: (rtype == 12).then(|| {
                rdata
                    .trim_end_matches('.')
                    .split('.')
                    .map(|label| label.as_bytes().to_vec())
                    .collect()
            }),
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
            app.query_history.insert(
                App::provenance_key(hostname, rtype),
                InterestQueryState {
                    transmitted: Some(sent_at),
                    ..InterestQueryState::default()
                },
            );
        }
    }

    fn live_ptr_rows(app: &App) -> Vec<browse::RawRecord> {
        app.services
            .iter()
            .flat_map(|s| s.ordered_answers())
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
        app.detail_selected = idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, idx));
    }

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
    fn txt_after_srv_lands_on_live_service() {
        // Passive-mode order: PTR, SRV (service confirmed), then TXT.
        // The late TXT must not strand in pending.
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        assert!(app.services[0]
            .ordered_answers()
            .iter()
            .all(|r| r.rtype != 16));
        ingest(&mut app, &txt_record("a=1; b=2"));
        assert!(app.services[0]
            .ordered_answers()
            .iter()
            .any(|r| r.rtype == 16));
    }

    #[test]
    fn subtype_after_srv_merges_into_live_service() {
        // Same passive-mode order for DNS-SD subtypes (e.g. Google Cast
        // group IDs under `..._sub._googlecast._tcp.local`).
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        assert!(app.services[0].subtypes.is_empty());
        ingest(
            &mut app,
            &raw_record(
                "_printer._sub._http._tcp.local.",
                12,
                "PTR",
                "Test._http._tcp.local.",
                120,
            ),
        );
        assert_eq!(app.services[0].subtypes, vec![b"_printer".to_vec()]);
        assert!(app.services[0]
            .ordered_answers()
            .iter()
            .any(|r| r.rtype == 12 && r.name == "_printer._sub._http._tcp.local."));
        // No stranded pending entry for the confirmed instance.
        assert!(app.pending_instances.is_empty());
    }

    #[test]
    fn subtype_without_underscore_and_restricted_characters_is_valid() {
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record(
                "%%0B3BFD96-5017-44DB-96E1-BEC3451F7DE2._sub._googlecast._tcp.local.",
                12,
                "PTR",
                "Google-Home._googlecast._tcp.local.",
                4500,
            ),
        );

        assert_eq!(
            app.pending_instances[0].subtypes,
            vec![b"%%0B3BFD96-5017-44DB-96E1-BEC3451F7DE2".to_vec()]
        );
        assert!(!app
            .anomalies()
            .iter()
            .any(|a| a.kind == anomalies::AnomalyKind::TypeFormat));
    }

    #[test]
    fn subtype_keeps_non_utf8_octets_and_escapes_them_in_service_dump() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));

        let label: &'static [u8] = Box::leak(vec![0xff, b'%'].into_boxed_slice());
        let labels: &'static [simple_dns::Label<'static>] = Box::leak(
            vec![
                simple_dns::Label::new_unchecked(label),
                simple_dns::Label::new_unchecked(&b"_sub"[..]),
                simple_dns::Label::new_unchecked(&b"_http"[..]),
                simple_dns::Label::new_unchecked(&b"_tcp"[..]),
                simple_dns::Label::new_unchecked(&b"local"[..]),
            ]
            .into_boxed_slice(),
        );
        let mut packet = simple_dns::Packet::new_reply(0);
        packet.answers.push(simple_dns::ResourceRecord::new(
            simple_dns::Name::new_with_labels(labels),
            simple_dns::CLASS::IN,
            4500,
            simple_dns::rdata::RData::PTR(
                simple_dns::Name::new_unchecked("Test._http._tcp.local.").into(),
            ),
        ));
        let bytes = packet.build_bytes_vec().unwrap();
        let event = browse::parse_packet(
            &bytes,
            test_source(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251)),
            "br0",
            3,
        )
        .unwrap();
        app.ingest_event(&event);

        assert_eq!(app.services[0].subtypes, vec![vec![0xff, b'%']]);
        assert_eq!(app.dump_service(&app.services[0]).subtypes, [r"\xFF%"]);
        assert!(!app
            .anomalies()
            .iter()
            .any(|a| a.kind == anomalies::AnomalyKind::TypeFormat));
    }

    #[test]
    fn service_types_match_case_insensitively() {
        // `_HTTP` and `_http` are one service (RFC 6763 §7); same for the
        // `._sub.` marker and instance matching.
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record(
                "_HTTP._TCP.LOCAL.",
                12,
                "PTR",
                "Test._HTTP._TCP.LOCAL.",
                120,
            ),
        );
        ingest(
            &mut app,
            &raw_record(
                "Test._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 test.local.",
                120,
            ),
        );
        assert_eq!(app.services.len(), 1);
        ingest(
            &mut app,
            &raw_record(
                "_PRINTER._SUB._http._tcp.local.",
                12,
                "PTR",
                "Test._http._tcp.local.",
                120,
            ),
        );
        assert_eq!(app.services.len(), 1);
        assert_eq!(app.services[0].subtypes.len(), 1);
        // One continuous interest, not one per case variant.
        let desired = app.desired_continuous();
        let ptr_keys: Vec<_> = desired.keys().filter(|(_, t)| *t == 12).collect();
        assert!(ptr_keys.iter().any(|(n, _)| n == "_http._tcp.local"));
        assert_eq!(
            ptr_keys
                .iter()
                .filter(|(n, _)| n.eq_ignore_ascii_case("_http._tcp.local"))
                .count(),
            1
        );
    }

    #[test]
    fn non_ascii_instance_names_do_not_panic_split() {
        // `é` is two bytes in UTF-8: byte-slicing at `len - known.len()`
        // can land inside the character. Splitting must skip such
        // candidates instead of panicking in `split_at`.
        let mut app = App::new().unwrap();
        app.known_types.insert("_https._tcp.local".to_string());
        assert!(app.split_instance_type("é._ssh._tcp.local").is_none());
        assert_eq!(
            App::strip_suffix_ci("é._ssh._tcp.local", "_https._tcp.local"),
            None
        );
        // Sanity: ASCII suffix matching still works.
        assert_eq!(
            App::strip_suffix_ci("Test._http._tcp.local", "_HTTP._TCP.LOCAL"),
            Some("Test")
        );
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
        assert!(!app.detail_free_scroll);
        // Ctrl+J now dumps state (like the sibling); viewport scroll
        // uses J instead.
        app.handle_key(&plain(KeyCode::Char('J')));
        assert!(app.detail_free_scroll);
        assert_eq!(app.detail_offset.get(), 1);
        app.handle_key(&ctrl(KeyCode::Char('k')));
        assert_eq!(app.detail_offset.get(), 0);
        // Tab focuses Answers; moving the record cursor resumes follow.
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Answers);
        let before = app.detail_selected;
        assert!(before > 0);
        app.handle_key(&plain(KeyCode::Char('k')));
        assert!(!app.detail_free_scroll);
        assert_eq!(app.detail_selected, before - 1);
        // Tab cycles Answers -> Questions -> Anomalies -> Hex -> Services.
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Questions);
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Anomalies);
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Hex);
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Services);
    }

    #[test]
    fn state_dump_models_mex_state() {
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "b=2; a=1");
        // known_types (the browse set) is learned on the send tick.
        app.send_queries();
        let dump = app.state_dump();
        assert!(!dump.passive);
        assert_eq!(dump.services.len(), 1);
        let svc = &dump.services[0];
        assert_eq!(svc.instance, "Test");
        assert_eq!(svc.service_type, "_http._tcp.local");
        assert_eq!(svc.hostname, "test.local.");
        assert_eq!(svc.port, 80);
        // TXT pairs sorted by key.
        assert_eq!(svc.txt_records, vec!["a=1".to_string(), "b=2".to_string()]);
        assert!(svc.is_active);
        assert!(!svc.answers.is_empty());
        assert!(dump.service_types.contains(&"_http._tcp.local".to_string()));
        // Top-level keys are mex's own model.
        let v = serde_json::to_value(&dump).unwrap();
        for key in [
            "metadata",
            "passive",
            "services",
            "service_types",
            "metrics",
            "enum_groups",
            "pending",
        ] {
            assert!(v.get(key).is_some(), "missing {key}");
        }
        assert_eq!(v["metadata"]["application_name"], "mex");
        assert_eq!(v["services"][0]["service_type"], "_http._tcp.local");
    }

    #[test]
    fn dump_redacts_high_entropy_txt_values() {
        let mut app = App::new().unwrap();
        service_with_txt(
            &mut app,
            "id=328FEBD442638273B38340E9AFE1E9CB; external_url=https://ha.knulp.home64.de; fn=Schreibtisch",
        );
        app.send_queries();
        let dump = app.state_dump();
        let svc = &dump.services[0];
        assert_eq!(
            svc.txt_records,
            vec![
                "external_url=*REDACTED*".to_string(),
                "fn=Schreibtisch".to_string(),
                "id=*REDACTED*".to_string()
            ]
        );
        let txt = svc
            .answers
            .iter()
            .find(|r| r.rtype_str == "TXT")
            .expect("TXT answer present");
        assert_eq!(
            txt.rdata,
            "id=*REDACTED*; external_url=*REDACTED*; fn=Schreibtisch"
        );
    }

    #[test]
    fn save_state_dump_to_writes_json_file() {
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "a=1");
        let dir = std::env::temp_dir().join(format!(
            "mex-dump-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let json_path = app.save_state_dump_to(&dir).unwrap();
        let json = std::fs::read_to_string(&json_path).unwrap();
        let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
        assert_eq!(parsed["metadata"]["application_name"], "mex");
        assert!(parsed.get("services").is_some());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn status_popup_shows_while_fresh() {
        use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
        let mut app = App::new().unwrap();
        assert!(app.status_popup().is_none());
        app.status_msg = Some(("hello".to_string(), Instant::now()));
        assert_eq!(app.status_popup().as_deref(), Some("hello"));
        // Any key dismisses it.
        let plain = KeyEvent {
            code: KeyCode::Char('x'),
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        };
        app.handle_key(&plain);
        assert!(app.status_popup().is_none());
    }

    #[test]
    fn dump_redacts_public_ipv6_addresses() {
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "a=1");
        ingest(
            &mut app,
            &raw_record("test.local.", 28, "AAAA", "2003:e8:bf10:9500::1", 120),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 28, "AAAA", "fd00::1", 120),
        );
        app.send_queries();
        let dump = app.state_dump();
        let svc = &dump.services[0];
        assert!(svc.addresses.contains(&"fd00::1".to_string()));
        assert!(svc.addresses.contains(&"2003:*REDACTED*:1".to_string()));
        assert!(!svc.addresses.iter().any(|a| a.contains("bf10")));
        let aaaa: Vec<_> = svc
            .answers
            .iter()
            .filter(|r| r.rtype_str == "AAAA")
            .collect();
        assert!(!aaaa.is_empty());
        for r in aaaa {
            assert!(!r.rdata.contains("bf10"), "global AAAA leaked: {}", r.rdata);
        }
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
        assert_eq!(app.focus, Focus::Services);
        // Service navigation in the Services pane: j moves to the next
        // selectable stop (Test).
        let stops = selectable_positions(&app);
        let test = stops[2];
        app.handle_key(&plain(KeyCode::Char('j')));
        assert_eq!(app.selected_display, test);
        let detail_before = app.detail_selected;
        // Tab focuses Answers: j now moves the record cursor instead.
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Answers);
        app.handle_key(&plain(KeyCode::Char('j')));
        assert_eq!(app.selected_display, test);
        assert_eq!(app.detail_selected, detail_before + 1);
        // BackTab steps back to Services.
        app.handle_key(&plain(KeyCode::BackTab));
        assert_eq!(app.focus, Focus::Services);
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
            let sel_idx = match app.display_items().get(app.selected_display) {
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
        assert_eq!(app.focus, Focus::Answers);
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Questions);
        assert_eq!(app.detail_selected, raw_count);
        // j/k stay inside the question rows; the selection is untouched.
        let selected_before = app.selected_display;
        app.handle_key(&plain(KeyCode::Char('j')));
        assert_eq!(app.detail_selected, raw_count + 1);
        assert_eq!(app.selected_display, selected_before);
        app.handle_key(&plain(KeyCode::Char('k')));
        assert_eq!(app.detail_selected, raw_count);
        app.handle_key(&plain(KeyCode::Home));
        assert_eq!(app.detail_selected, raw_count);
        app.handle_key(&plain(KeyCode::End));
        assert_eq!(app.detail_selected, raw_count + 1);
        // Enter has nothing to expand here and must not fold the host.
        app.handle_key(&plain(KeyCode::Enter));
        assert!(app.collapsed_hosts.is_empty());
    }

    #[test]
    fn own_questions_filed_on_type_full_and_host() {
        let mut app = two_group_app();
        // Type-level: only the _http service matches.
        app.route_own_question("_http._tcp.local.", 12, false);
        assert_eq!(app.services[0].questions.len(), 1);
        assert!(app.services[1].questions.is_empty());
        let q = &app.services[0].questions[0];
        assert_eq!(q.0, "_http._tcp.local");
        assert_eq!(q.1, "PTR");
        assert_eq!(q.2, SELF_SOURCE);
        assert!(browse::question_fields(&q.4, &q.0, &q.1).is_some());
        // Full instance name and host name file further rows.
        app.route_own_question("Test._http._tcp.local.", 33, false);
        app.route_own_question("test.local.", 1, false);
        assert_eq!(app.services[0].questions.len(), 3);
        // Re-sending refreshes instead of duplicating.
        app.route_own_question("_http._tcp.local.", 12, false);
        assert_eq!(app.services[0].questions.len(), 3);
        // Enumeration files on its own row, unknown types file nothing.
        app.route_own_question("_services._dns-sd._udp.local.", 12, false);
        app.route_own_question("_http._tcp.local.", 99, false);
        assert_eq!(app.services[0].questions.len(), 3);
        assert!(app.services[1].questions.is_empty());
        assert_eq!(app.enum_entries.len(), 1);
        assert_eq!(app.enum_entries[0].questions.len(), 1);
    }

    #[test]
    fn own_question_packet_preserves_qu_bit() {
        let mut app = two_group_app();
        app.route_own_question("Shell._ssh._tcp.local.", 12, true);
        let question = app
            .services
            .iter()
            .flat_map(|service| &service.questions)
            .find(|question| question.2 == SELF_SOURCE)
            .expect("self question was filed");
        let fields = browse::question_fields(&question.4, &question.0, &question.1)
            .expect("inferred query packet has question fields");
        let qclass = fields
            .iter()
            .find(|field| field.label == "QCLASS / QU")
            .expect("question has QCLASS / QU field");
        assert_eq!(&question.4[qclass.start..qclass.end], &[0x80, 0x01]);
    }

    #[test]
    fn discovery_self_question_survives_promotion() {
        let mut app = App::new().unwrap();
        // PTR first: the instance lives in pending, no service yet.
        ingest(&mut app, &ptr_record(120));
        assert!(app.services.is_empty());
        assert_eq!(app.pending_instances.len(), 1);
        // Our continuous stream asks for the pending SRV: parked, not dropped.
        app.route_own_question("Test._http._tcp.local.", 33, false);
        assert!(app.services.is_empty());
        assert_eq!(app.pending_instances[0].questions.len(), 1);
        // The SRV reply promotes the service with the question kept.
        ingest(&mut app, &srv_record(120));
        assert!(app.pending_instances.is_empty());
        let filed: Vec<_> = app.services[0]
            .questions
            .iter()
            .filter(|q| q.2 == SELF_SOURCE)
            .collect();
        assert_eq!(filed.len(), 1);
        assert_eq!(filed[0].1, "SRV");
    }

    #[test]
    fn active_sends_file_self_questions() {
        let mut app = due_query_setup();
        assert!(app.services[0].questions.is_empty());
        app.send_queries();
        assert_eq!(app.metrics.q_sent_refresh, 1);
        let filed: Vec<_> = app.services[0]
            .questions
            .iter()
            .filter(|q| q.2 == SELF_SOURCE)
            .collect();
        assert_eq!(filed.len(), 1);
        assert_eq!(filed[0].1, "PTR");
    }

    #[test]
    fn self_question_hex_title_matches_remote() {
        let mut app = two_group_app();
        // Remote question with packet bytes on the selected service.
        let remote: std::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();
        let pkt = vec![0x12, 0x34, 0x01, 0x00];
        {
            let sel_idx = match app.display_items().get(app.selected_display) {
                Some(DisplayItem::Instance { index }) => *index,
                _ => panic!("expected instance selected"),
            };
            app.services[sel_idx].questions.push((
                "_ssh._tcp.local".to_string(),
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
            let sel_idx = match app.display_items().get(app.selected_display) {
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
        app.detail_selected = raws + self_pos;
        let (bytes, title) = app
            .selected_detail_bytes()
            .expect("self question has hex payload");
        assert_ne!(bytes, fallback);
        assert!(browse::question_fields(&bytes, "_ssh._tcp.local", "PTR").is_some());
        assert_eq!(title, " QRY PTR _ssh._tcp.local (inferred) ");
        // Remote row returns its own query packet bytes under the
        // unmarked title.
        app.detail_selected = raws + remote_pos;
        let (rbytes, remote_title) = app
            .selected_detail_bytes()
            .expect("remote question has hex payload");
        assert_eq!(rbytes, pkt);
        assert_eq!(remote_title, " QRY PTR _ssh._tcp.local ");
    }

    #[test]
    fn enum_self_question_hex_title_matches_remote() {
        let mut app = App::new().unwrap();
        let enum_pos = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Enum { .. }))
            .expect("enum row");
        app.selected_display = enum_pos;
        app.clamp_selection();
        let remote: std::net::SocketAddr = "192.168.1.99:5353".parse().unwrap();
        app.enum_entries[0].questions.push((
            "_services._dns-sd._udp.local".to_string(),
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
        app.detail_selected = raws + self_pos;
        let (bytes, title) = app
            .selected_detail_bytes()
            .expect("self enum question has hex payload");
        assert!(browse::question_fields(&bytes, "_services._dns-sd._udp.local", "PTR").is_some());
        assert_eq!(title, " QRY PTR _services._dns-sd._udp.local (inferred) ");
    }

    /// Render the full UI into a test buffer at the given size. Shared
    /// core for the render-based regression tests below.
    fn render_to_buffer(app: &App, width: u16, height: u16) -> ratatui::buffer::Buffer {
        use ratatui::backend::TestBackend;
        let mut terminal = ratatui::Terminal::new(TestBackend::new(width, height)).unwrap();
        terminal.draw(|f| crate::ui::draw(f, app)).unwrap();
        terminal.backend().buffer().clone()
    }

    /// REVERSED-carrying cell styles inside the Questions pane body
    /// (border and header rows excluded). No other style in that pane uses
    /// REVERSED, so any hit is the cursor marker.
    fn questions_reversed_modifiers(app: &App) -> Vec<ratatui::style::Modifier> {
        // Rects are recorded during draw, so render first.
        let buf = render_to_buffer(app, 100, 30);
        let area = app.questions_rect.get();
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
        let area = app.hex_rect.get();
        let mut s = String::new();
        for x in area.x..(area.x + area.width) {
            if let Some(cell) = buf.cell((x, area.y)) {
                s.push_str(cell.symbol());
            }
        }
        s
    }

    #[test]
    fn unicast_question_routes_as_info_with_display_key() {
        // End-to-end through the real routing path: an observed SOA
        // question lands on the service as an info-level unicast-question
        // finding (RFC 6762 §3 makes asking compliant), stays off the
        // service badge, and carries exactly the (name, type, querier)
        // triple the Questions pane looks up.
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
        let mut q = raw_record("test.local.", 6, "SOA", "", 120);
        q.source = querier;
        app.ingest_event(&browse::Event {
            answers: Vec::new(),
            questions: vec![q],
            query_kas: Vec::new(),
            rcode: None,
            received_at: Instant::now(),
            raw_bytes: vec![0x01, 0x02],
            source: querier,
        });
        let item = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind == anomalies::AnomalyKind::UnicastQuestion)
            .expect("expected routed SOA question leak");
        assert_eq!(item.service, "Test._http._tcp.local");
        assert_eq!(item.severity, crate::anomalies::Severity::Info);
        assert_eq!(
            app.anomaly_counts()
                .get("Test._http._tcp.local")
                .copied()
                .unwrap_or(0),
            0,
            "info-level question findings stay off the service badge"
        );
        assert_eq!(
            (
                item.record_name
                    .unwrap()
                    .trim_end_matches('.')
                    .to_lowercase(),
                item.rtype.unwrap(),
                item.source.unwrap(),
            ),
            ("test.local".to_string(), 6, querier.to_string()),
            "finding must carry the exact display lookup triple"
        );
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
        app.detail_selected = raws + self_pos;
        // Hosts focus: dimmed marker, hex title names the question.
        assert_eq!(app.focus, Focus::Services);
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
        app.focus = Focus::Questions;
        let marked = questions_reversed_modifiers(&app);
        assert!(!marked.is_empty());
        assert!(
            marked.iter().all(|m| !m.contains(Modifier::DIM)),
            "focused cursor must not be dimmed"
        );
        assert!(hex_title_line(&app).contains("QRY PTR _ssh._tcp.local"));
        // Hex focus: dimmed marker, same title.
        app.focus = Focus::Hex;
        let marked = questions_reversed_modifiers(&app);
        assert!(!marked.is_empty());
        assert!(marked.iter().all(|m| m.contains(Modifier::DIM)));
        assert!(hex_title_line(&app).contains("QRY PTR _ssh._tcp.local"));
        // Moving the cursor across question rows updates marker and title.
        {
            let sel_idx = match app.display_items().get(app.selected_display) {
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
        app.detail_selected = raws + remote_pos;
        let marked = questions_reversed_modifiers(&app);
        assert!(!marked.is_empty());
        assert!(hex_title_line(&app).contains("QRY A shell.local"));
    }

    /// Hex pane body cell modifiers (excluding the two dump header lines)
    /// plus the hex pane title line, rendered at the given terminal size.
    fn hex_body_marks(
        app: &App,
        width: u16,
        height: u16,
    ) -> (Vec<ratatui::style::Modifier>, String) {
        let buf = render_to_buffer(app, width, height);
        let area = app.hex_rect.get();
        let empty =
            app.selected_detail_bytes().is_none() && app.latest_event_for_selected().is_none();
        let offset = app.hex_offset.get();
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
            0x04, b'_', b's', b's', b'h', 0x04, b'_', b't', b'c', b'p', 0x05, b'l', b'o', b'c',
            b'a', b'l', 0x00, 0x00, 0x0c, 0x00, 0x01, 0x00, 0x00, 0x00, 0x78, 0x00, 0x17, 0x05,
            b'S', b'h', b'e', b'l', b'l', 0x04, b'_', b's', b's', b'h', 0x04, b'_', b't', b'c',
            b'p', 0x05, b'l', b'o', b'c', b'a', b'l', 0x00,
        ];
        app.services
            .iter_mut()
            .find(|service| service.instance == "Shell")
            .and_then(|service| service.answers.iter_mut().find(|record| record.rtype == 33))
            .expect("SRV record")
            .wire = srv_wire();
        app.detail_selected = 0;

        let before = render_to_buffer(&app, 160, 60);
        let selected_record = app.detail_selected;
        let (field_x, field_y) =
            find_buffer_text(&before, "Owner name").expect("owner field is displayed");
        app.mouse_down(field_x + 1, field_y);
        assert_eq!(
            app.detail_selected, selected_record,
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
        let hex_area = app.hex_rect.get();
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
        app.focus = Focus::Answers;
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
        let selected_row = app.detail_selected;
        app.mouse_down(field_x + 1, field_y);
        assert_eq!(
            app.detail_selected, selected_row,
            "clicking a question field should preserve the selected row"
        );

        let after = render_to_buffer(&app, 160, 60);
        let (class_x, class_y) = find_buffer_text(&after, "0001 0553 6865")
            .expect("second question bytes are displayed");
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
        let hex_area = app.hex_rect.get();
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
        let selected_service = match app.display_items().get(app.selected_display) {
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
        app.detail_selected = raw_count;
        app.focus = Focus::Questions;

        let before = render_to_buffer(&app, 160, 60);
        assert!(
            find_buffer_text(&before, "(inferred)").is_some(),
            "own question bytes should be identified as inferred"
        );
        let (field_x, field_y) =
            find_buffer_text(&before, "QNAME").expect("own question name field is displayed");
        let selected_row = app.detail_selected;
        app.mouse_down(field_x + 1, field_y);
        assert_eq!(
            app.detail_selected, selected_row,
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
        app.detail_selected = app
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
        app.detail_selected = app
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
        app.detail_selected = app
            .display_detail()
            .and_then(|detail| {
                detail
                    .ordered_answers()
                    .iter()
                    .position(|record| record.rtype == 99)
            })
            .expect("unknown record position");

        let buffer = render_to_buffer(&app, 160, 60);
        let hex_area = app.hex_rect.get();
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
        app.detail_selected = app
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
        app.focus = Focus::Hex;
        let (mods, _) = hex_body_marks(&app, 100, 30);
        assert!(!mods.is_empty());
        assert!(
            mods.iter().any(|m| m.contains(Modifier::BOLD)),
            "focused hex body must be bold"
        );
        app.focus = Focus::Services;
        let (mods, _) = hex_body_marks(&app, 100, 30);
        assert!(!mods.is_empty());
        assert!(
            mods.iter().all(|m| !m.contains(Modifier::BOLD)),
            "unfocused hex body must not be bold"
        );
        // Empty state: cue present, same rule.
        let mut empty_app = App::new().unwrap();
        empty_app.focus = Focus::Hex;
        let (mods, _) = hex_body_marks(&empty_app, 100, 30);
        assert!(mods.iter().any(|m| m.contains(Modifier::BOLD)));
        empty_app.focus = Focus::Services;
        let (mods, _) = hex_body_marks(&empty_app, 100, 30);
        assert!(mods.iter().all(|m| !m.contains(Modifier::BOLD)));
        // Scrolled state: tall dump, small pane, offset forced.
        let mut app = two_group_app();
        {
            let sel_idx = match app.display_items().get(app.selected_display) {
                Some(DisplayItem::Instance { index }) => *index,
                _ => panic!("expected instance selected"),
            };
            app.services[sel_idx]
                .last_event
                .as_mut()
                .expect("last event")
                .raw_bytes = vec![0xAB; 256];
        }
        app.hex_offset.set(5);
        app.focus = Focus::Hex;
        // Tall enough that the scrolled dump keeps a viewport in the
        // four-pane stack.
        let (mods, title) = hex_body_marks(&app, 100, 20);
        assert!(title.contains('↕'), "dump must be scrolled, got: {title}");
        assert!(mods.iter().any(|m| m.contains(Modifier::BOLD)));
        app.focus = Focus::Services;
        let (mods, _) = hex_body_marks(&app, 100, 20);
        assert!(mods.iter().all(|m| !m.contains(Modifier::BOLD)));
    }

    #[test]
    fn enum_answers_file_on_selectable_row() {
        let mut app = App::new().unwrap();
        assert_eq!(app.enum_entries.len(), 1);
        ingest(
            &mut app,
            &raw_record(
                "_services._dns-sd._udp.local.",
                12,
                "PTR",
                "_http._tcp.local.",
                120,
            ),
        );
        assert!(app.known_types.contains("_http._tcp.local"));
        assert_eq!(app.enum_entries[0].answers.len(), 1);
        assert_eq!(app.group_labels()[0], "(enumeration)");
        // Metrics carry a per-name row for the enumeration name.
        let rows = app.metrics_rows();
        assert!(rows.iter().any(|(k, _)| k.contains("_dns-sd._udp")));
    }

    #[test]
    fn enum_questions_observed_and_own() {
        let mut app = App::new().unwrap();
        let ev = query_event(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            false,
            Vec::new(),
            remote_source(),
        );
        app.ingest_event(&ev);
        assert_eq!(app.enum_entries[0].questions.len(), 1);
        assert!(app.services.iter().all(|s| s.questions.is_empty()));
        app.route_own_question("_services._dns-sd._udp.local.", 12, false);
        assert_eq!(app.enum_entries[0].questions.len(), 2);
        assert_eq!(app.enum_entries[0].questions[1].2, SELF_SOURCE);
    }

    #[test]
    fn enum_query_kas_never_become_answers() {
        // Sibling-style enumeration query: one question plus known answers
        // (RFC 6762 §7.1). KAs are beliefs, not sightings: in passive mode
        // (or any mode) they must never land in the Answers pane nor in the
        // known-answer bookkeeping. A genuine response still files normally.
        let mut app = App::new().unwrap();
        app.passive = true;
        let kas = [
            "_dacp._tcp.local.",
            "_mass._tcp.local.",
            "_http._tcp.local.",
        ]
        .iter()
        .map(|t| ka_record("_services._dns-sd._udp.local.", t))
        .collect();
        let ev = query_event(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            false,
            kas,
            remote_source(),
        );
        app.ingest_event(&ev);
        assert_eq!(app.enum_entries[0].questions.len(), 1);
        assert!(
            app.enum_entries[0].answers.is_empty(),
            "query KAs must not become enumeration answers"
        );
        assert!(
            app.enum_known.is_empty(),
            "query KAs must not seed known-answer bookkeeping"
        );
        assert!(app.known_types.is_empty());

        let ans = raw_record(
            "_services._dns-sd._udp.local.",
            12,
            "PTR",
            "_dacp._tcp.local.",
            4500,
        );
        let ev = event_for(&ans);
        app.ingest_event(&ev);
        assert_eq!(app.enum_entries[0].answers.len(), 1);
        assert!(app.enum_known.contains_key("_dacp._tcp.local"));
        assert!(app.known_types.contains("_dacp._tcp.local"));
    }

    /// REVERSED-carrying cell styles inside the Answers pane body (border
    /// and header rows excluded). Backs the unfocused-marker regression
    /// test; no other style in that pane uses REVERSED, so any hit is the
    /// cursor marker.
    fn answers_reversed_modifiers(app: &App) -> Vec<ratatui::style::Modifier> {
        let buf = render_to_buffer(app, 100, 30);
        let area = app.answers_rect.get();
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

    #[test]
    fn answers_table_marks_hex_source_when_hosts_focused() {
        use ratatui::style::Modifier;
        let mut app = two_group_app();
        // Services focus is the Hosts pane.
        assert_eq!(app.focus, Focus::Services);
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
        app.focus = Focus::Answers;
        let marked = answers_reversed_modifiers(&app);
        assert!(!marked.is_empty());
        assert!(
            marked.iter().all(|m| !m.contains(Modifier::DIM)),
            "focused cursor must not be dimmed"
        );
        // Moving the host selection keeps marker and hex dump in sync: the
        // marker follows the detail cursor (test answers carry no wire
        // bytes, so the dump itself is covered by the title tests).
        app.focus = Focus::Services;
        select_instance(&mut app, "Test");
        assert!(app.selected_detail_entry().is_some());
        let marked = answers_reversed_modifiers(&app);
        assert!(!marked.is_empty(), "marker must follow the host selection");
    }

    #[test]
    fn enum_answers_coalesce_wire_case_variants() {
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record(
                "_services._dns-sd._udp.local.",
                12,
                "PTR",
                "_http._tcp.local.",
                120,
            ),
        );
        // Same answer in different wire case: DNS names compare
        // case-insensitively, so this refreshes the row instead of
        // growing the list.
        ingest(
            &mut app,
            &raw_record(
                "_SERVICES._DNS-SD._UDP.LOCAL.",
                12,
                "PTR",
                "_HTTP._TCP.LOCAL.",
                120,
            ),
        );
        assert_eq!(app.enum_entries[0].answers.len(), 1);
    }

    #[test]
    fn enum_subtype_targets_with_lossy_collisions_remain_distinct() {
        let target = |byte: u8| {
            let subtype: &'static [u8] = Box::leak(vec![byte].into_boxed_slice());
            let labels: &'static [simple_dns::Label<'static>] = Box::leak(
                vec![
                    simple_dns::Label::new_unchecked(subtype),
                    simple_dns::Label::new_unchecked(&b"_sub"[..]),
                    simple_dns::Label::new_unchecked(&b"_http"[..]),
                    simple_dns::Label::new_unchecked(&b"_tcp"[..]),
                    simple_dns::Label::new_unchecked(&b"local"[..]),
                ]
                .into_boxed_slice(),
            );
            simple_dns::Name::new_with_labels(labels)
        };
        let mut packet = simple_dns::Packet::new_reply(0);
        for byte in [0xfe, 0xff] {
            packet.answers.push(simple_dns::ResourceRecord::new(
                simple_dns::Name::new_unchecked("_services._dns-sd._udp.local."),
                simple_dns::CLASS::IN,
                4500,
                simple_dns::rdata::RData::PTR(target(byte).into()),
            ));
        }
        let bytes = packet.build_bytes_vec().unwrap();
        let event = browse::parse_packet(
            &bytes,
            test_source(),
            std::net::IpAddr::V4(std::net::Ipv4Addr::new(224, 0, 0, 251)),
            "br0",
            3,
        )
        .unwrap();
        let mut app = App::new().unwrap();
        app.ingest_event(&event);

        assert_eq!(app.enum_entries[0].answers.len(), 2);
        assert_eq!(app.enum_entries[0].ordered_answers().len(), 2);
        let messages: Vec<_> = app
            .anomalies()
            .into_iter()
            .filter(|anomaly| anomaly.kind == anomalies::AnomalyKind::EnumSubtype)
            .map(|anomaly| anomaly.message)
            .collect();
        assert_eq!(messages.len(), 2);
        assert!(messages.iter().any(|message| message.contains(r"\xFE")));
        assert!(messages.iter().any(|message| message.contains(r"\xFF")));
    }

    #[test]
    fn header_falls_back_to_last_selected_kind() {
        let mut app = two_group_app();
        select_instance(&mut app, "Shell");
        // Select the enumeration row, then collapse its group and park
        // on the collapsed header.
        let enum_pos = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Enum { .. }))
            .expect("enum row");
        app.selected_display = enum_pos;
        app.clamp_selection();
        assert!(app.selected_enum().is_some());
        app.collapsed_hosts.insert(ENUM_HOST.to_string());
        let header_pos = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Host { label } if label == ENUM_HOST))
            .expect("enum header");
        app.selected_display = header_pos;
        app.clamp_selection();
        assert!(app.selected_service().is_none());
        assert!(app.selected_enum().is_none());
        let target = app.display_detail().expect("sticky target survives header");
        assert!(
            matches!(target, DetailTarget::Enum(_)),
            "collapsed header must show the last selected kind, not a stale service"
        );
    }

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
    fn enum_gets_qu_on_first_send() {
        let mut app = App::new().unwrap();
        app.poll_continuous(); // seeds the enumeration interest
        let past = Instant::now() - Duration::from_millis(1);
        app.continuous
            .get_mut(&(ENUM_SERVICE.to_string().to_lowercase(), 12))
            .expect("enum interest seeded")
            .next_due = past;
        app.poll_continuous();
        assert_eq!(app.metrics.qu_sent, 1);
        assert_eq!(app.metrics.q_sent_continuous, 1);
    }

    #[test]
    fn passive_mode_files_no_self_questions() {
        let setup = due_query_setup();
        let mut app = setup;
        app.passive = true;
        app.send_queries();
        assert!(app.services.iter().all(|s| s.questions.is_empty()));
    }

    #[test]
    fn reverse_ptr_creates_no_pending_service() {
        // Reverse-mapping PTRs map addresses to hostnames; they are not
        // service enumeration and must not seed (phantom) services.
        let mut app = App::new().unwrap();
        let rec = raw_record(
            "Android.local.37.178.168.192.in-addr.arpa.",
            12,
            "PTR",
            "Android.local.",
            120,
        );
        let ev = browse::Event {
            answers: vec![rec],
            questions: vec![],
            query_kas: vec![],
            rcode: Some(0),
            received_at: Instant::now(),
            raw_bytes: vec![],
            source: test_source(),
        };
        app.ingest_event(&ev);
        assert!(app.services.is_empty());
        assert!(app.pending_instances.is_empty());
        assert!(
            app.anomalies()
                .iter()
                .all(|a| a.kind != anomalies::AnomalyKind::TypeFormat),
            "reverse name must not flag"
        );
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
    fn metrics_overlay_omits_self_referential_rdata() {
        // PTR rdata usually names its own service (here each PTR seeds
        // its own service identity); repeating it after the scope adds no
        // identity beyond the service column, so it stays short — while
        // the two services still tell apart.
        let mut app = App::new().unwrap();
        let mut first = ptr_record(4500);
        first.flush_bit = true;
        ingest(&mut app, &first);
        let mut second = raw_record(
            "_http._tcp.local.",
            12,
            "PTR",
            "Other._http._tcp.local.",
            4500,
        );
        second.flush_bit = true;
        ingest(&mut app, &second);
        ingest(&mut app, &srv_record(120));
        let values: Vec<String> = app
            .metrics_rows()
            .into_iter()
            .filter(|(k, _)| k.ends_with("shared-flush"))
            .map(|(_, v)| v)
            .collect();
        assert_eq!(values.len(), 2, "both findings listed, got: {values:?}");
        assert!(
            !values.iter().any(|v| v.contains(" = ")),
            "self rdata stays short, got: {values:?}"
        );
        assert_ne!(values[0], values[1], "rows must differ, got: {values:?}");
    }

    #[test]
    fn metrics_enum_question_keeps_qry_scope() {
        // Questions on the enumeration row keep their QRY scope: the
        // queried type varies, so suppressing it would collapse NS and
        // SOA askers into identical rows.
        let mut app = App::new().unwrap();
        let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
        app.ingest_event(&query_event(
            "_services._dns-sd._udp.local.",
            2,
            "NS",
            false,
            Vec::new(),
            stub,
        ));
        let row = app
            .metrics_rows()
            .into_iter()
            .find(|(k, _)| k.ends_with("unicast-question"))
            .expect("unicast-question row");
        assert!(
            row.1.contains("QRY NS _services._dns-sd._udp.local"),
            "enum question keeps its QRY scope, got: {}",
            row.1
        );
    }

    #[test]
    fn anomalies_pane_omits_info_question_on_enumeration_row() {
        let mut app = App::new().unwrap();
        let stub: SocketAddr = "192.168.1.9:45678".parse().unwrap();
        app.ingest_event(&query_event(
            "_services._dns-sd._udp.local.",
            6,
            "SOA",
            false,
            Vec::new(),
            stub,
        ));
        app.evict_expired();
        let enum_pos = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Enum { .. }))
            .expect("enum row");
        app.selected_display = enum_pos;
        app.clamp_selection();
        park_on_question(&mut app, stub);
        let buf = render_to_buffer(&app, 140, 30);
        let text = rect_text(&buf, app.anomalies_rect.get());
        // Info-level question findings live in the overlay only.
        assert!(
            !text.contains("QRY SOA"),
            "pane omits info question findings, got: {text:?}"
        );
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
        app.record_viewport.set(2);
        app.handle_key(&key(KeyCode::Tab));
        app.handle_key(&key(KeyCode::End));
        assert_eq!(app.detail_selected, 2);
        app.handle_key(&key(KeyCode::Home));
        assert_eq!(app.detail_selected, 0);
        app.handle_key(&key(KeyCode::Char(' ')));
        assert_eq!(app.detail_selected, 2);
        app.handle_key(&key(KeyCode::Char('b')));
        assert_eq!(app.detail_selected, 0);
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

    fn select_question_row(app: &mut App, name: &str, rtype: &str, packet: Vec<u8>) {
        let raw_count = app
            .display_detail()
            .expect("selected service")
            .ordered_answers()
            .len();
        let selected_service = match app.display_items().get(app.selected_display) {
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
        app.detail_selected = raw_count;
        app.focus = Focus::Questions;
    }

    /// Move the cursor onto the instance row with this name.
    fn select_instance(app: &mut App, instance: &str) {
        let items = app.display_items();
        for (i, it) in items.iter().enumerate() {
            if let DisplayItem::Instance { index } = it {
                if app.services[*index].instance == instance {
                    app.selected_display = i;
                    break;
                }
            }
        }
        app.clamp_selection();
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
    fn groups_by_hostname_with_unknown_last() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // Second service without hostname yet: instance known via PTR only
        // would normally sit in pending; force a service with empty host.
        app.services.push(ServiceEntry {
            instance: "Lonely".to_string(),
            service_type: "_http._tcp.local".to_string(),
            hostname: String::new(),
            port: 0,
            subtypes: Vec::new(),
            answers: Vec::new(),
            questions: Vec::new(),
            questions_dropped: 0,
            last_seen: Instant::now(),
            is_active: true,
            last_event: None,
        });
        app.evict_expired();
        let labels: Vec<String> = app
            .display_items()
            .into_iter()
            .filter_map(|it| match it {
                DisplayItem::Host { label } => Some(label),
                _ => None,
            })
            .collect();
        assert_eq!(
            labels,
            vec![
                "(enumeration)".to_string(),
                "test.local".to_string(),
                String::new()
            ]
        );
        assert_eq!(app.host_display_name("test.local"), "test");
        assert_eq!(app.host_display_name(""), "(unknown host)");
        assert_eq!(app.host_service_count("test.local"), 1);
        assert_eq!(app.host_service_count(""), 1);
    }

    #[test]
    fn host_display_name_strips_redundant_local_suffix() {
        let app = App::new().unwrap();
        assert_eq!(app.host_display_name("printer.local"), "printer");
        assert_eq!(app.host_display_name("printer.local."), "printer");
        assert_eq!(app.host_display_name("printer.LOCAL"), "printer");
        // Bare `local` or `local` mid-name is not a suffix: untouched.
        assert_eq!(app.host_display_name("local"), "local");
        assert_eq!(app.host_display_name("mylocal"), "mylocal");
        assert_eq!(app.host_display_name("local.domain"), "local.domain");
    }

    #[test]
    fn host_addresses_ipv4_first_live_only() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // A + AAAA for the same host, plus a duplicate and an expired row.
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 28, "AAAA", "fe80::1", 120),
        );
        ingest(&mut app, &raw_record("test.local.", 1, "A", "10.0.0.9", 0));
        let addrs = app.host_addresses("test.local");
        assert_eq!(
            addrs,
            vec!["192.168.1.10".to_string(), "fe80::1".to_string()]
        );
        // (+N) suffix shows additional addresses beyond the primary.
        assert_eq!(addrs.len() - 1, 1);
    }

    /// Two instances of one type sharing a single hostname: the shape
    /// behind the fan-out bug (many SRVs, one host).
    fn two_on_shared_host_app() -> App {
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "Two._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record(
                "One._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 shared.local.",
                120,
            ),
        );
        ingest(
            &mut app,
            &raw_record(
                "Two._http._tcp.local.",
                33,
                "SRV",
                "0 0 8080 shared.local.",
                120,
            ),
        );
        assert_eq!(app.services.len(), 2);
        app
    }

    fn has_live_a(app: &App, instance: &str) -> bool {
        app.services
            .iter()
            .find(|s| s.instance == instance)
            .expect("service present")
            .answers
            .iter()
            .any(|r| {
                r.rtype == 1
                    && r.rdata == "192.168.1.10"
                    && r.ttl > r.received_at.elapsed().as_secs() as u32
            })
    }

    #[test]
    fn shared_hostname_a_record_reaches_every_service() {
        let mut app = two_on_shared_host_app();
        ingest(
            &mut app,
            &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
        );
        assert!(has_live_a(&app, "One"), "A missing on One");
        assert!(has_live_a(&app, "Two"), "A missing on Two");
    }

    #[test]
    fn late_joiner_backfills_shared_hostname_a_record() {
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "Two._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record(
                "One._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 shared.local.",
                120,
            ),
        );
        // Address lands while only One is confirmed: it must still reach
        // Two once its SRV promotes it.
        ingest(
            &mut app,
            &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record(
                "Two._http._tcp.local.",
                33,
                "SRV",
                "0 0 8080 shared.local.",
                120,
            ),
        );
        assert_eq!(app.services.len(), 2);
        assert!(has_live_a(&app, "One"), "A missing on One");
        assert!(has_live_a(&app, "Two"), "A missing on late joiner Two");
    }

    #[test]
    fn shared_hostname_a_goodbye_reaches_every_service() {
        let mut app = two_on_shared_host_app();
        ingest(
            &mut app,
            &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
        );
        assert!(has_live_a(&app, "One") && has_live_a(&app, "Two"));
        ingest(
            &mut app,
            &raw_record("shared.local.", 1, "A", "192.168.1.10", 0),
        );
        // Both services keep the row as an expired goodbye; neither keeps
        // a live address, and both stay browsable (A never deactivates).
        for instance in ["One", "Two"] {
            let svc = app
                .services
                .iter()
                .find(|s| s.instance == instance)
                .expect("service present");
            assert!(
                svc.answers
                    .iter()
                    .any(|r| r.rtype == 1 && r.rdata == "192.168.1.10" && r.ttl == 0),
                "goodbye row missing on {instance}"
            );
            assert!(!has_live_a(&app, instance), "live A stranded on {instance}");
            assert!(svc.is_active, "{instance} deactivated by an A goodbye");
        }
    }

    #[test]
    fn pending_address_flush_reaches_every_service() {
        let mut app = App::new().unwrap();
        // Address arrives before either SRV: no hostname matches, so it
        // parks in pending_addrs. The ingest helper never flushes, which
        // is exactly what this exercises.
        ingest(
            &mut app,
            &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record("shared.local.", 1, "A", "192.168.1.11", 120),
        );
        assert!(app.services.is_empty());
        assert_eq!(app.pending_addrs_count(), 2);
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "Two._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record(
                "One._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 shared.local.",
                120,
            ),
        );
        ingest(
            &mut app,
            &raw_record(
                "Two._http._tcp.local.",
                33,
                "SRV",
                "0 0 8080 shared.local.",
                120,
            ),
        );
        // Backfill finds no sibling rows (nothing flushed yet), so the
        // parked address is still pending until the drain-time flush.
        app.flush_pending_addrs();
        assert!(app.pending_addrs.is_empty());
        for instance in ["One", "Two"] {
            let service = app
                .services
                .iter()
                .find(|service| service.instance == instance)
                .unwrap();
            assert_eq!(
                service.answers.iter().filter(|r| r.rtype == 1).count(),
                2,
                "pending A records missing on {instance}"
            );
        }
    }

    #[test]
    fn unrelated_packet_batch_does_not_flush_pending_addresses() {
        let mut app = App::new_with(true, None).unwrap();
        let (tx, rx) = mpsc::channel();
        app.rx = rx;

        tx.send(event_for(&raw_record(
            "test.local.",
            1,
            "A",
            "192.168.1.10",
            120,
        )))
        .unwrap();
        app.drain_events();
        assert_eq!(app.pending_addrs_count(), 1);

        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));

        tx.send(event_for(&raw_record(
            "unrelated.local.",
            1,
            "A",
            "192.168.1.11",
            120,
        )))
        .unwrap();
        app.drain_events();

        assert!(app.pending_addrs.contains_key("test.local"));

        tx.send(event_for(&srv_record(120))).unwrap();
        app.drain_events();

        assert!(!app.pending_addrs.contains_key("test.local"));
        assert!(has_live_a(&app, "Test"));
    }

    #[test]
    fn pending_address_flush_includes_live_alternate_srv_targets() {
        let mut app = App::new_with(true, None).unwrap();
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "Svc._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record(
                "Svc._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 host-a.local.",
                120,
            ),
        );
        ingest(
            &mut app,
            &raw_record(
                "Svc._http._tcp.local.",
                33,
                "SRV",
                "0 0 8080 host-b.local.",
                120,
            ),
        );
        app.pending_addrs.insert(
            "host-a.local".to_string(),
            vec![raw_record("host-a.local.", 1, "A", "192.168.1.10", 120)],
        );
        app.flush_pending_addrs();

        assert!(app.pending_addrs.is_empty());
        assert_eq!(app.services[0].hostname, "host-b.local.");
        assert!(app.services[0]
            .answers
            .iter()
            .any(|r| r.rtype == 1 && r.rdata == "192.168.1.10"));
    }

    #[test]
    fn backfill_ignores_sibling_rows_from_old_hostname() {
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "Two._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record("One._http._tcp.local.", 33, "SRV", "0 0 80 old.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record("old.local.", 1, "A", "192.168.0.5", 120),
        );
        // One moves to the shared host; its old-host rows stay put.
        ingest(
            &mut app,
            &raw_record(
                "One._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 shared.local.",
                120,
            ),
        );
        // Promoting Two must not inherit One's old-host address.
        ingest(
            &mut app,
            &raw_record(
                "Two._http._tcp.local.",
                33,
                "SRV",
                "0 0 8080 shared.local.",
                120,
            ),
        );
        let two = app
            .services
            .iter()
            .find(|s| s.instance == "Two")
            .expect("Two present");
        assert!(
            two.answers.iter().all(|r| r.rtype != 1 && r.rtype != 28),
            "old-host address leaked onto Two"
        );
        let one = app
            .services
            .iter()
            .find(|s| s.instance == "One")
            .expect("One present");
        assert!(one
            .answers
            .iter()
            .any(|r| r.rtype == 1 && r.rdata == "192.168.0.5"));
    }

    #[test]
    fn host_name_does_not_flap_on_alternating_srv_targets() {
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "Svc._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record(
                "Svc._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 host-a.local.",
                120,
            ),
        );
        assert_eq!(app.services[0].hostname, "host-a.local.");
        assert_eq!(app.services[0].port, 80);
        // A genuinely new target moves the service.
        ingest(
            &mut app,
            &raw_record(
                "Svc._http._tcp.local.",
                33,
                "SRV",
                "0 0 8080 host-b.local.",
                120,
            ),
        );
        assert_eq!(app.services[0].hostname, "host-b.local.");
        assert_eq!(app.services[0].port, 8080);
        // Refreshing the now-known alternate target must not flip back or
        // change the selected target's port.
        ingest(
            &mut app,
            &raw_record(
                "Svc._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 host-a.local.",
                120,
            ),
        );
        assert_eq!(app.services[0].hostname, "host-b.local.");
        assert_eq!(app.services[0].port, 8080);
        ingest(
            &mut app,
            &raw_record(
                "Svc._http._tcp.local.",
                33,
                "SRV",
                "0 0 8080 host-b.local.",
                120,
            ),
        );
        assert_eq!(app.services[0].hostname, "host-b.local.");
        assert_eq!(app.services[0].port, 8080);
        // Addresses published only under the alternate target are still
        // filed on the service and surfaced on the selected host.
        ingest(
            &mut app,
            &raw_record("host-a.local.", 1, "A", "192.168.1.10", 120),
        );
        assert!(app.services[0]
            .answers
            .iter()
            .any(|r| r.rtype == 1 && r.rdata == "192.168.1.10"));
        assert!(app
            .host_addresses("host-b.local")
            .contains(&"192.168.1.10".to_string()));
        // A refresh after expiry of the alternate-target address is still
        // routed and displayed.
        ingest(
            &mut app,
            &raw_record("host-a.local.", 1, "A", "192.168.1.10", 0),
        );
        assert!(!app
            .host_addresses("host-b.local")
            .contains(&"192.168.1.10".to_string()));
        ingest(
            &mut app,
            &raw_record("host-a.local.", 1, "A", "192.168.1.10", 120),
        );
        assert!(app
            .host_addresses("host-b.local")
            .contains(&"192.168.1.10".to_string()));
        for rec in &mut app.services[0].answers {
            if rec.rtype == 1 && rec.rdata == "192.168.1.10" {
                rec.received_at = Instant::now() - Duration::from_secs(121);
            }
        }
        assert!(!app
            .host_addresses("host-b.local")
            .contains(&"192.168.1.10".to_string()));
        ingest(
            &mut app,
            &raw_record("host-a.local.", 1, "A", "192.168.1.10", 120),
        );
        assert!(app
            .host_addresses("host-b.local")
            .contains(&"192.168.1.10".to_string()));
    }

    #[test]
    fn stale_alternate_target_does_not_route_addr_goodbye() {
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "Svc._http._tcp.local.", 120),
        );
        ingest(
            &mut app,
            &raw_record(
                "Svc._http._tcp.local.",
                33,
                "SRV",
                "0 0 80 host-b.local.",
                120,
            ),
        );
        app.services[0].answers.push(raw_record(
            "Svc._http._tcp.local.",
            33,
            "SRV",
            "0 0 80 host-a.local.",
            0,
        ));
        ingest(
            &mut app,
            &raw_record("host-a.local.", 1, "A", "192.168.1.10", 0),
        );
        assert!(!app.services[0]
            .answers
            .iter()
            .any(|r| r.rtype == 1 && r.rdata == "192.168.1.10"));
        assert!(!app
            .host_addresses("host-b.local")
            .contains(&"192.168.1.10".to_string()));
    }

    #[test]
    fn addr_on_withdrawn_service_keeps_grace_deadline() {
        let mut app = two_on_shared_host_app();
        ingest(
            &mut app,
            &raw_record("shared.local.", 1, "A", "192.168.1.10", 120),
        );
        // Withdraw One; it lingers inactive through the grace period.
        ingest(
            &mut app,
            &raw_record("_http._tcp.local.", 12, "PTR", "One._http._tcp.local.", 0),
        );
        let deadline = app
            .services
            .iter()
            .find(|s| s.instance == "One")
            .expect("One present")
            .last_seen;
        assert!(
            !app.services
                .iter()
                .find(|s| s.instance == "One")
                .expect("One present")
                .is_active
        );
        // A subsequent shared-host announcement still files its row...
        ingest(
            &mut app,
            &raw_record("shared.local.", 1, "A", "192.168.1.11", 120),
        );
        let one = app
            .services
            .iter()
            .find(|s| s.instance == "One")
            .expect("One present");
        assert!(one
            .answers
            .iter()
            .any(|r| r.rtype == 1 && r.rdata == "192.168.1.11"));
        // ...without extending the grace deadline; the sibling is unaffected.
        assert_eq!(one.last_seen, deadline);
        assert!(has_live_a(&app, "Two"));
    }

    #[test]
    fn jk_moves_service_selection() {
        let mut app = two_group_app();
        // Cursor starts on Shell; j moves to Test, k back to Shell.
        let shell = selectable_positions(&app)[1];
        let test = selectable_positions(&app)[2];
        assert_eq!(app.selected_display, shell);
        app.handle_key(&plain_key(KeyCode::Char('j')));
        assert_eq!(app.selected_display, test);
        app.handle_key(&plain_key(KeyCode::Char('k')));
        assert_eq!(app.selected_display, shell);
    }

    #[test]
    fn hl_jumps_between_groups() {
        let mut app = two_group_app();
        let stops = selectable_positions(&app);
        let (first, shell, test) = (stops[0], stops[1], stops[2]);
        assert_eq!(app.selected_display, shell);
        app.handle_key(&plain_key(KeyCode::Char('l')));
        assert_eq!(app.selected_display, test);
        app.handle_key(&plain_key(KeyCode::Char('h')));
        assert_eq!(app.selected_display, shell);
        // Shift jumps to the first/last group.
        app.handle_key(&plain_key(KeyCode::Char('L')));
        assert_eq!(app.selected_display, *stops.last().unwrap());
        app.handle_key(&plain_key(KeyCode::Char('H')));
        assert_eq!(app.selected_display, first);
    }

    #[test]
    fn arrows_jump_between_groups_like_hl() {
        let mut app = two_group_app();
        let stops = selectable_positions(&app);
        let (shell, test) = (stops[1], stops[2]);
        assert_eq!(app.selected_display, shell);
        app.handle_key(&plain_key(KeyCode::Right));
        assert_eq!(app.selected_display, test);
        app.handle_key(&plain_key(KeyCode::Left));
        assert_eq!(app.selected_display, shell);
    }

    #[test]
    fn home_end_and_space_paging() {
        let mut app = two_group_app();
        app.list_viewport.set(2);
        let stops = selectable_positions(&app);
        let (first, last) = (stops[0], *stops.last().unwrap());
        app.handle_key(&plain_key(KeyCode::End));
        assert_eq!(app.selected_display, last);
        app.handle_key(&plain_key(KeyCode::Home));
        assert_eq!(app.selected_display, first);
        // Space pages down one viewport (2 stops); b pages back up.
        app.handle_key(&plain_key(KeyCode::Char(' ')));
        assert_eq!(app.selected_display, stops[2]);
        assert!(app.collapsed_hosts.is_empty());
        app.handle_key(&plain_key(KeyCode::Char('b')));
        assert_eq!(app.selected_display, first);
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
        assert_eq!(app.focus, Focus::Answers);
        let cursor = app.detail_selected;
        // Uppercase, with and without SHIFT flagged (terminal-dependent).
        app.handle_key(&plain(KeyCode::Char('J')));
        app.handle_key(&shift(KeyCode::Char('J')));
        assert_eq!(app.detail_offset.get(), 2);
        assert_eq!(app.detail_selected, cursor);
        app.handle_key(&plain(KeyCode::Char('K')));
        app.handle_key(&shift(KeyCode::Char('K')));
        assert_eq!(app.detail_offset.get(), 0);
        assert_eq!(app.detail_selected, cursor);
        // Lowercase + SHIFT (other keyboard protocols) scrolls too and
        // never moves the cursor.
        app.handle_key(&shift(KeyCode::Char('j')));
        assert_eq!(app.detail_offset.get(), 1);
        assert_eq!(app.detail_selected, cursor);
        app.handle_key(&shift(KeyCode::Char('k')));
        assert_eq!(app.detail_offset.get(), 0);
        assert_eq!(app.detail_selected, cursor);
        assert!(app.detail_free_scroll);
        // Plain lowercase still moves the cursor instead of scrolling.
        app.handle_key(&plain(KeyCode::Char('k')));
        assert_eq!(app.detail_selected, cursor - 1);
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
        // Tab reaches Hex after Anomalies; the focused pane lights its border.
        app.handle_key(&plain(KeyCode::Tab));
        app.handle_key(&plain(KeyCode::Tab));
        app.handle_key(&plain(KeyCode::Tab));
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Hex);
        // Viewport is recorded at draw; fake 10 rows for the scroll math.
        app.hex_viewport.set(10);
        app.handle_key(&plain(KeyCode::Char('j')));
        assert_eq!(app.hex_offset.get(), 1);
        app.handle_key(&plain(KeyCode::Char(' ')));
        assert_eq!(app.hex_offset.get(), 11);
        app.handle_key(&plain(KeyCode::Home));
        assert_eq!(app.hex_offset.get(), 0);
        app.handle_key(&plain(KeyCode::End));
        assert!(app.hex_offset.get() > 1000);
        // Moving the record cursor restarts the dump at the top.
        app.handle_key(&plain(KeyCode::BackTab));
        app.handle_key(&plain(KeyCode::BackTab));
        app.handle_key(&plain(KeyCode::BackTab));
        assert_eq!(app.focus, Focus::Answers);
        app.handle_key(&plain(KeyCode::Char('k')));
        assert_eq!(app.hex_offset.get(), 0);
        // Clicking another row restarts the dump; re-clicking keeps scroll.
        app.answers_rect.set(Rect::new(33, 3, 67, 30));
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        app.detail_offset.set(0);
        app.hex_offset.set(5);
        app.click_answers(3 + 2 + 1);
        assert_eq!(app.detail_selected, 0);
        assert_eq!(app.hex_offset.get(), 0);
        app.hex_offset.set(5);
        app.click_answers(3 + 2 + 1);
        assert_eq!(app.hex_offset.get(), 5);
        // Clicking the hex pane focuses it for scrolling.
        app.left_rect.set(Rect::new(0, 3, 33, 30));
        app.answers_rect.set(Rect::new(33, 3, 67, 8));
        app.questions_rect.set(Rect::new(33, 11, 67, 7));
        app.anomalies_rect.set(Rect::new(33, 18, 67, 6));
        app.hex_rect.set(Rect::new(33, 24, 67, 9));
        app.focus = Focus::Services;
        app.mouse_down(40, 25);
        assert_eq!(app.focus, Focus::Hex);
    }

    #[test]
    fn hex_offset_resets_on_target_change() {
        let mut app = two_group_app();
        app.hex_offset.set(7);
        select_instance(&mut app, "Test");
        assert_eq!(app.hex_offset.get(), 0);
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
            for rec in &mut svc.answers {
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
    fn query_provenance_records_transmit_suppress_observe() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // Age the SRV into the refresh window so a refresh is due.
        for svc in &mut app.services {
            for rec in &mut svc.answers {
                if rec.rtype == 33 {
                    rec.received_at = Instant::now() - Duration::from_secs(100);
                }
            }
        }
        app.requery_expiring();
        // No overheard query: the SRV refresh is transmitted.
        let srv_key = ("test._http._tcp.local".to_string(), 33);
        let prov = app
            .query_history
            .get(&srv_key)
            .expect("provenance recorded");
        assert!(prov.transmitted.is_some());
        assert!(matches!(
            prov.last().map(|(o, _)| o),
            Some(QueryOrigin::Transmitted)
        ));

        // A remote QM question for the same key suppresses the next
        // refresh (§7.3): the KA set is empty on both sides.
        let ev = query_event(
            "Test._http._tcp.local.",
            33,
            "SRV",
            false,
            Vec::new(),
            remote_source(),
        );
        app.ingest_event(&ev);
        let prov = app.query_history.get(&srv_key).expect("observed recorded");
        assert!(prov.observed.is_some());
        // Make the refresh due again: the schedule spaces attempts ~5%
        // of TTL apart, so without backdating the second run skips it.
        for ((name, rtype), (due, _)) in app.requeries.iter_mut() {
            if name == "Test._http._tcp.local" && *rtype == 33 {
                *due = Instant::now() - Duration::from_secs(1);
            }
        }
        app.requery_expiring();
        let prov = app.query_history.get(&srv_key).expect("still there");
        assert!(prov.suppressed.is_some());
        assert!(matches!(
            prov.last().map(|(o, _)| o),
            Some(QueryOrigin::Suppressed)
        ));

        // An unrelated observed question records observation only.
        let ev = query_event(
            "_printer._tcp.local.",
            12,
            "PTR",
            false,
            Vec::new(),
            remote_source(),
        );
        app.ingest_event(&ev);
        let prov = app
            .query_history
            .get(&("_printer._tcp.local".to_string(), 12))
            .expect("observed recorded");
        assert!(prov.observed.is_some());
        assert!(prov.transmitted.is_none());
        assert!(prov.suppressed.is_none());
    }

    #[test]
    fn query_provenance_prunes_dead_interests() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        // Recent provenance for a live interest survives eviction.
        app.note_query(
            "_http._tcp.local",
            12,
            QueryOrigin::Transmitted,
            Instant::now(),
        );
        // Stale provenance with no live schedule is dropped.
        app.query_history.insert(
            ("gone._tcp.local".to_string(), 12),
            InterestQueryState {
                transmitted: Some(Instant::now() - Duration::from_secs(3600)),
                ..Default::default()
            },
        );
        app.evict_expired();
        assert!(app
            .query_history
            .contains_key(&("_http._tcp.local".to_string(), 12)));
        assert!(!app
            .query_history
            .contains_key(&("gone._tcp.local".to_string(), 12)));
    }

    #[test]
    fn interest_view_reports_timer_and_status() {
        let mut app = App::new().unwrap();
        // Unknown interest: no schedule, no answers, no history.
        let view = app.interest_view(&("_http._tcp.local".to_string(), 12));
        assert_eq!(view.timer, TimerKind::Expired);
        assert_eq!(view.status, InterestStatus::Abandoned);
        assert_eq!(view.attempt, 0);
        assert!(view.next_due.is_none());
        assert!(view.origin().is_none());

        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // Continuous stream exists after a poll; no refresh due yet.
        app.poll_continuous();
        let view = app.interest_view(&("_http._tcp.local".to_string(), 12));
        assert_eq!(view.timer, TimerKind::Browse);
        assert!(view.next_due.is_some());
        // Live answers, nothing pending: answered.
        assert_eq!(view.status, InterestStatus::Answered);

        // Age the SRV into the refresh window: the refresh timer wins
        // over the continuous stream and the send is recorded.
        for svc in &mut app.services {
            for rec in &mut svc.answers {
                if rec.rtype == 33 {
                    rec.received_at = Instant::now() - Duration::from_secs(100);
                }
            }
        }
        app.requery_expiring();
        let view = app.interest_view(&("test._http._tcp.local".to_string(), 33));
        assert_eq!(view.timer, TimerKind::Refresh);
        assert_eq!(view.status, InterestStatus::Transmitted);
        assert_eq!(view.attempt, 1);
        assert_eq!(view.origin(), Some(QueryOrigin::Transmitted));
    }

    #[test]
    fn dump_reports_interest_query_state_and_truncation() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // Age the SRV into the refresh window and drive one refresh.
        for svc in &mut app.services {
            for rec in &mut svc.answers {
                if rec.rtype == 33 {
                    rec.received_at = Instant::now() - Duration::from_secs(100);
                }
            }
        }
        app.requery_expiring();
        let dump = app.state_dump();
        let srv = dump
            .interests
            .iter()
            .find(|i| i.rtype == 33)
            .expect("srv interest");
        assert_eq!(srv.timer, "refresh");
        assert_eq!(srv.status, "transmitted");
        assert!(srv.attempt >= 1);
        assert!(srv.next_due_in_secs.is_some());
        assert_eq!(srv.last_origin.as_deref(), Some("transmitted"));
        assert!(srv.last_transmitted_age_secs.is_some());
        assert!(srv.last_suppressed_age_secs.is_none());
        assert!(srv.last_observed_age_secs.is_none());

        // Flood one service question from distinct sources past the cap
        // (the earlier self SRV refresh already holds one row, so 10 more
        // pushes evict exactly once).
        for i in 0..10 {
            let src: std::net::SocketAddr = format!("192.168.1.{}:5353", 10 + i).parse().unwrap();
            let mut ev = query_event("_http._tcp.local.", 12, "PTR", false, Vec::new(), src);
            ev.questions[0].iface = "br0".to_string();
            app.ingest_event(&ev);
        }
        let dump = app.state_dump();
        let svc = &dump.services[0];
        assert_eq!(svc.questions.len(), 10);
        assert!(svc.questions_truncated);
        assert_eq!(svc.questions_dropped, 1);
        // The interest records who asked last and on which link.
        let ptr = dump
            .interests
            .iter()
            .find(|i| i.name == "_http._tcp.local" && i.rtype == 12)
            .expect("ptr interest");
        assert_eq!(ptr.last_origin.as_deref(), Some("observed"));
        assert!(ptr.last_observed_age_secs.is_some());
        assert!(ptr.last_transmitted_age_secs.is_none());
        assert_eq!(ptr.last_observed_from.as_deref(), Some("192.168.1.19:5353"));
        assert_eq!(ptr.last_observed_iface.as_deref(), Some("br0"));
    }

    #[test]
    fn pihole_cycle_expires_after_four_misses_then_rescues() {
        // Regression fixture for the observed Pi-hole sequence: repeated
        // 120s SRV records expiring after unanswered refreshes, then
        // renewed when another browse elicits the SRV as additional data.
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        let age_srv = |app: &mut App, secs: u64| {
            for svc in &mut app.services {
                for rec in &mut svc.answers {
                    if rec.rtype == 33 {
                        rec.received_at = Instant::now() - Duration::from_secs(secs);
                    }
                }
            }
        };
        age_srv(&mut app, 100);
        // Four unanswered refreshes: attempts 1-3 stay pending, the
        // fourth expires the schedule.
        for expected in 1u8..=4u8 {
            for ((name, rtype), (due, _)) in app.requeries.iter_mut() {
                if name == "Test._http._tcp.local" && *rtype == 33 {
                    *due = Instant::now() - Duration::from_secs(1);
                }
            }
            app.requery_expiring();
            if expected < 4 {
                let view = app.interest_view(&("test._http._tcp.local".to_string(), 33));
                assert_eq!(view.status, InterestStatus::Transmitted);
                assert_eq!(view.attempt, expected);
            }
        }
        assert!(!app
            .requeries
            .keys()
            .any(|(n, t)| n == "Test._http._tcp.local" && *t == 33));
        assert_eq!(app.metrics.q_sent_refresh, 4);
        // Row past TTL with no pending refresh: abandoned, while the
        // continuous stream stays live for hourly rediscovery (§5.2).
        age_srv(&mut app, 130);
        let key = ("test._http._tcp.local".to_string(), 33);
        let view = app.interest_view(&key);
        assert_eq!(view.timer, TimerKind::Browse);
        assert_eq!(view.status, InterestStatus::Abandoned);
        // Another browser's PTR browse rescues the SRV as additional
        // data: fresh row, no false self query, provenance intact.
        let questions_before: usize = app.services.iter().map(|s| s.questions.len()).sum();
        let mut rescue = event_for(&srv_record(120));
        rescue.source = remote_source();
        for rec in &mut rescue.answers {
            rec.source = remote_source();
        }
        app.ingest_event(&rescue);
        let view = app.interest_view(&key);
        assert_eq!(view.status, InterestStatus::Answered);
        assert_eq!(view.attempt, 0);
        assert_eq!(view.origin(), Some(QueryOrigin::Transmitted));
        let questions_after: usize = app.services.iter().map(|s| s.questions.len()).sum();
        assert_eq!(questions_before, questions_after);
    }

    #[test]
    fn dump_lists_answer_only_interests() {
        // Passive mode files answers without any query activity: the
        // authoritative interests section must still list them, with
        // origin absent rather than invented.
        let mut app = App::new_with(true, None).unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        let dump = app.state_dump();
        let ptr = dump
            .interests
            .iter()
            .find(|i| i.name == "_http._tcp.local" && i.rtype == 12)
            .expect("ptr interest listed");
        assert_eq!(ptr.status, "answered");
        assert!(ptr.last_origin.is_none());
        let srv = dump
            .interests
            .iter()
            .find(|i| i.name == "test._http._tcp.local" && i.rtype == 33)
            .expect("srv interest listed");
        assert_eq!(srv.status, "answered");
    }

    #[test]
    fn pending_addrs_count_as_live_answers() {
        let mut app = App::new().unwrap();
        // An A record arrives before any SRV names the host: parked in
        // pending_addrs, still a live answer for the interest.
        let mut rec = raw_record("lonely.local.", 1, "A", "192.168.1.9", 120);
        rec.source = remote_source();
        ingest(&mut app, &rec);
        assert_eq!(app.pending_addrs_count(), 1);
        let view = app.interest_view(&("lonely.local".to_string(), 1));
        assert_eq!(view.status, InterestStatus::Answered);
    }

    #[test]
    fn repeated_unmatched_addresses_do_not_accumulate() {
        let mut app = App::new().unwrap();
        for _ in 0..8 {
            ingest(
                &mut app,
                &raw_record("lonely.local.", 1, "A", "192.168.1.9", 120),
            );
        }
        assert_eq!(app.pending_addrs_count(), 1);
    }

    #[test]
    fn expired_unmatched_addresses_are_evicted() {
        let mut app = App::new().unwrap();
        let mut rec = raw_record("lonely.local.", 1, "A", "192.168.1.9", 1);
        rec.received_at = Instant::now() - Duration::from_secs(2);
        ingest(&mut app, &rec);
        assert_eq!(app.pending_addrs_count(), 1);

        app.next_pending_addr_prune = Instant::now();
        app.evict_expired();

        assert!(app.pending_addrs.is_empty());
    }

    #[test]
    fn state_dump_reports_pending_address_count() {
        let mut app = App::new_with(true, None).unwrap();
        ingest(
            &mut app,
            &raw_record("lonely.local.", 1, "A", "192.168.1.9", 120),
        );

        assert_eq!(app.state_dump().metrics["pending_addrs"], 1);
    }

    #[test]
    fn provenance_lookup_folds_non_ascii_case() {
        let mut app = App::new().unwrap();
        // A requery entry keyed in wire case (U+00C9 É, U+00E9 é) must
        // be found through its lowercase form (U+00E9 é): explicit
        // code points keep the test independent of the editor's
        // composed/decomposed accent handling, which to_lowercase does
        // not normalize away.
        let wire_case = "\u{00C9}tag\u{00E9}._http._tcp.local";
        let lower_case = "\u{00E9}tag\u{00E9}._http._tcp.local";
        app.requeries.insert(
            (wire_case.to_string(), 12),
            (Instant::now() + Duration::from_secs(60), 2),
        );
        let view = app.interest_view(&(lower_case.to_string(), 12));
        assert_eq!(view.timer, TimerKind::Refresh);
        assert_eq!(view.attempt, 2);
    }

    /// Full text of the Questions pane (header + body) for render
    /// assertions on columns and cell labels.
    fn questions_pane_text(app: &App) -> String {
        let buf = render_to_buffer(app, 120, 40);
        let area = app.questions_rect.get();
        let mut out = String::new();
        for y in area.y..(area.y + area.height) {
            for x in area.x..(area.x + area.width) {
                if let Some(cell) = buf.cell((x, y)) {
                    out.push_str(cell.symbol());
                }
            }
            out.push('\n');
        }
        out
    }

    #[test]
    fn questions_pane_shows_last_and_due() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        select_instance(&mut app, "Test");
        // Continuous stream exists (browse timer); SRV refresh due now.
        app.poll_continuous();
        for svc in &mut app.services {
            for rec in &mut svc.answers {
                if rec.rtype == 33 {
                    rec.received_at = Instant::now() - Duration::from_secs(100);
                }
            }
        }
        app.requery_expiring();
        // An observed PTR question from a peer.
        let ev = query_event(
            "_http._tcp.local.",
            12,
            "PTR",
            false,
            Vec::new(),
            remote_source(),
        );
        app.ingest_event(&ev);
        // An observed-only question for a type we never schedule: no
        // local demand exists, so DUE must stay blank, not "expired".
        let mut soa = raw_record("test.local.", 6, "SOA", "", 120);
        soa.source = remote_source();
        app.ingest_event(&browse::Event {
            answers: Vec::new(),
            questions: vec![soa],
            query_kas: Vec::new(),
            rcode: None,
            received_at: Instant::now(),
            raw_bytes: vec![0x01, 0x02],
            source: remote_source(),
        });
        // Backdate the last transmit past the old fixed column width:
        // the full kind word must survive, not clip.
        if let Some(s) = app
            .query_history
            .get_mut(&("test._http._tcp.local".to_string(), 33))
        {
            s.transmitted = Some(Instant::now() - Duration::from_secs(4000));
        }
        let text = questions_pane_text(&app);
        assert!(text.contains("LAST"), "header shows LAST:\n{text}");
        assert!(text.contains("DUE"), "header shows DUE:\n{text}");
        assert!(!text.contains("AGE"), "AGE column removed:\n{text}");
        assert!(text.contains("observed"), "observed kind shown:\n{text}");
        assert!(
            text.contains("transmitted"),
            "full kind word shown:\n{text}"
        );
        assert!(text.contains("refresh"), "refresh timer shown:\n{text}");
        // Foreign rows no longer inherit the interest's browse timer;
        // only self rows are schedule-driven, and this scenario has no
        // self PTR row, so "browse" is not rendered here.
        assert!(
            !text.contains("expired"),
            "foreign-only interest has no due:\n{text}"
        );
    }

    #[test]
    fn questions_pane_last_self_suppressed() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        select_instance(&mut app, "Test");
        app.poll_continuous();
        for svc in &mut app.services {
            for rec in &mut svc.answers {
                if rec.rtype == 33 {
                    rec.received_at = Instant::now() - Duration::from_secs(100);
                }
            }
        }
        app.requery_expiring();
        // Overhear a peer's SRV question so the next refresh is suppressed.
        let ev = query_event(
            "Test._http._tcp.local.",
            33,
            "SRV",
            false,
            Vec::new(),
            remote_source(),
        );
        app.ingest_event(&ev);
        for ((name, rtype), (due, _)) in app.requeries.iter_mut() {
            if name == "Test._http._tcp.local" && *rtype == 33 {
                *due = Instant::now() - Duration::from_secs(1);
            }
        }
        app.requery_expiring();
        let text = questions_pane_text(&app);
        assert!(
            text.contains("suppressed"),
            "suppressed kind shown:\n{text}"
        );
    }

    #[test]
    fn questions_pane_last_self_no_provenance() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        select_instance(&mut app, "Test");
        // File a self row without recording provenance: LAST must be blank.
        app.route_own_question("_http._tcp.local.", 12, false);
        let text = questions_pane_text(&app);
        assert!(text.contains("—"), "blank LAST shown:\n{text}");
        assert!(text.contains("PTR"), "ptr row shown:\n{text}");
    }

    #[test]
    fn questions_pane_last_foreign_observed() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        select_instance(&mut app, "Test");
        let ev = query_event(
            "_http._tcp.local.",
            12,
            "PTR",
            false,
            Vec::new(),
            remote_source(),
        );
        app.ingest_event(&ev);
        let text = questions_pane_text(&app);
        assert!(text.contains("observed"), "foreign row observed:\n{text}");
    }

    #[test]
    fn projected_refresh_beats_backed_off_browse() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        app.poll_continuous();
        // Back the continuous stream off to hourly: the projected
        // refresh at receipt + 80% TTL must own DUE instead.
        let key = ("test._http._tcp.local".to_string(), 33);
        app.continuous.get_mut(&key).unwrap().next_due = Instant::now() + Duration::from_secs(3600);
        let view = app.interest_view(&key);
        assert_eq!(view.timer, TimerKind::Refresh);
        let secs = view
            .next_due
            .unwrap()
            .saturating_duration_since(Instant::now())
            .as_secs();
        assert!((90..=96).contains(&secs), "due {secs}s out of window");
    }

    #[test]
    fn passive_browser_projects_no_refresh() {
        let mut app = App::new_with(true, None).unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // Live answers, but a passive browser transmits nothing: no
        // schedule, no projection, no false refresh countdown.
        let view = app.interest_view(&("test._http._tcp.local".to_string(), 33));
        assert_eq!(view.timer, TimerKind::Expired);
        assert_eq!(view.status, InterestStatus::Answered);
        assert!(view.next_due.is_none());
    }

    #[test]
    fn requery_postpones_continuous_for_same_key() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        // Age PTR into the 80-100% window so a refresh is due.
        for svc in &mut app.services {
            for rec in &mut svc.answers {
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
            owner_labels: name
                .trim_end_matches('.')
                .split('.')
                .map(|label| label.as_bytes().to_vec())
                .collect(),
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
        assert_eq!(app.metrics_scroll.get(), 0);
        assert_eq!(app.metrics_hscroll.get(), 0);
        app.handle_key(&key(KeyCode::Char('j')));
        assert_eq!(app.metrics_scroll.get(), 1);
        app.handle_key(&key(KeyCode::Char('k')));
        assert_eq!(app.metrics_scroll.get(), 0);
        // Uppercase reports the same intent.
        app.handle_key(&key(KeyCode::Char('J')));
        assert_eq!(app.metrics_scroll.get(), 1);
        app.handle_key(&key(KeyCode::Char('K')));
        assert_eq!(app.metrics_scroll.get(), 0);
        // Horizontal pan: h/l and arrows move one char, Ctrl jumps ten,
        // `0` jumps back. The key column stays frozen (no vertical move).
        app.handle_key(&key(KeyCode::Char('l')));
        assert_eq!(app.metrics_hscroll.get(), 1);
        app.handle_key(&key(KeyCode::Right));
        assert_eq!(app.metrics_hscroll.get(), 2);
        app.handle_key(&key(KeyCode::Char('h')));
        assert_eq!(app.metrics_hscroll.get(), 1);
        app.handle_key(&key(KeyCode::Left));
        assert_eq!(app.metrics_hscroll.get(), 0);
        app.handle_key(&key(KeyCode::Char('h')));
        assert_eq!(app.metrics_hscroll.get(), 0);
        let ctrl = |code| KeyEvent {
            code,
            modifiers: KeyModifiers::CONTROL,
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        };
        app.handle_key(&ctrl(KeyCode::Char('l')));
        assert_eq!(app.metrics_hscroll.get(), 10);
        app.handle_key(&ctrl(KeyCode::Right));
        assert_eq!(app.metrics_hscroll.get(), 20);
        app.handle_key(&key(KeyCode::Char('0')));
        assert_eq!(app.metrics_hscroll.get(), 0);
        assert_eq!(app.metrics_scroll.get(), 0);
        app.handle_key(&key(KeyCode::Char('k')));
        assert_eq!(app.metrics_scroll.get(), 0);
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
    fn pending_ptr_flush_is_analyzed() {
        // PTR with flush bit but no SRV yet: the row lives in pending, and
        // the analyzer must still see it.
        let mut app = App::new().unwrap();
        let mut bad = ptr_record(120);
        bad.flush_bit = true;
        ingest(&mut app, &bad);
        assert!(app.services.is_empty());
        assert!(!app.pending_instances.is_empty());
        assert!(app
            .anomalies()
            .iter()
            .any(|a| a.kind == anomalies::AnomalyKind::SharedFlush));
    }

    #[test]
    fn metrics_anomaly_rows_use_level_icons() {
        // Same fixture as above: a unique PTR with the flush bit is a
        // shared-record violation, so the metrics overlay lists it with
        // a Nerd Font level icon instead of the severity word.
        let mut app = App::new().unwrap();
        let mut bad = ptr_record(120);
        bad.flush_bit = true;
        ingest(&mut app, &bad);
        let found = app.anomalies();
        let a = found
            .iter()
            .find(|a| a.kind == anomalies::AnomalyKind::SharedFlush)
            .expect("finding");
        let icon = App::anomaly_level_icon(a.severity);
        let rows = app.metrics_rows();
        let (k, v) = rows
            .iter()
            .find(|(k, _)| k.starts_with(icon))
            .expect("anomaly row");
        assert_eq!(k, &format!("{icon} shared-flush"));
        assert!(
            v.starts_with("192.168.1.2:5353: "),
            "source leads the value, got: {v}"
        );
        assert!(v.contains(&a.service), "value names the service, got: {v}");
        assert!(
            v.contains("PTR _http._tcp.local."),
            "value names the pointed-to row, got: {v}"
        );
        assert!(
            !k.contains(a.severity.as_str()),
            "no severity word left, got: {k}"
        );
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
        app.continuous.insert(
            ("_http._tcp.local".to_string(), 12),
            ContinuousQuery {
                next_due: Instant::now() - Duration::from_millis(1),
                interval: Duration::from_secs(2),
                qname: "_http._tcp.local".to_string(),
            },
        );
        app
    }

    #[test]
    fn active_mode_sends_due_queries() {
        let mut app = due_query_setup();
        app.send_queries();
        assert_eq!(app.metrics.q_sent_refresh, 1);
        // The refresh postpones the continuous twin for the same key
        // instead of emitting back-to-back duplicates.
        assert_eq!(app.metrics.q_sent_continuous, 0);
        let entry = app
            .continuous
            .get(&("_http._tcp.local".to_string(), 12))
            .expect("still scheduled");
        assert!(entry.next_due > Instant::now());
    }

    #[test]
    fn passive_mode_sends_nothing() {
        let setup = due_query_setup();
        let due = setup
            .continuous
            .get(&("_http._tcp.local".to_string(), 12))
            .expect("seeded entry")
            .next_due;
        let mut app = setup;
        app.passive = true;
        app.send_queries();
        let entry = app
            .continuous
            .get(&("_http._tcp.local".to_string(), 12))
            .expect("still scheduled");
        assert_eq!(entry.next_due, due);
        assert_eq!(entry.interval, Duration::from_secs(2));
        assert_eq!(app.metrics.q_sent_continuous, 0);
        assert_eq!(app.metrics.q_sent_refresh, 0);
        assert!(app.requeries.is_empty());
        assert!(!app.startup_qu_sent);
    }

    #[test]
    fn passive_constructor_sets_flag() {
        assert!(!App::new().unwrap().passive);
        assert!(App::new_with(true, None).unwrap().passive);
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
        assert!(app.is_selectable(&items[app.selected_display]));
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
        app.body_rect.set(Rect::new(0, 3, 100, 40));
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        app.set_left_from_x(5);
        assert_eq!(app.left_pct, 15);
        app.set_left_from_x(50);
        assert_eq!(app.left_pct, 50);
        app.questions_pct = 25;
        app.anomalies_pct = 20;
        app.set_answers_from_y(3 + 27);
        assert_shares(&app);
        app.answers_pct = 30;
        app.anomalies_pct = 20;
        app.set_middle_from_y(3 + 27);
        assert_shares(&app);
        app.answers_pct = 30;
        app.questions_pct = 25;
        app.set_lower_from_y(3 + 27);
        assert_shares(&app);
    }

    #[test]
    fn mouse_click_anomalies_focuses_without_moving_cursor() {
        let mut app = two_group_app();
        app.focus = Focus::Services;
        let cursor = app.detail_selected;
        // Click against the computed layout, not hand-placed rects.
        render_to_buffer(&app, 100, 30);
        let area = app.anomalies_rect.get();
        assert!(area.height > 2, "anomalies pane needs an interior row");
        // Interior click (not a seam): focuses the pane, leaves the
        // cursor and both dump offsets alone.
        app.anomalies_offset.set(2);
        app.hex_offset.set(4);
        app.mouse_down(area.x + 2, area.y + 1);
        assert_eq!(app.focus, Focus::Anomalies);
        assert_eq!(app.detail_selected, cursor);
        assert_eq!(app.anomalies_offset.get(), 2);
        assert_eq!(app.hex_offset.get(), 4);
    }

    #[test]
    fn anomalies_pane_pages_with_paging_keys() {
        use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "a=1; b=2");
        let plain = |code| KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        };
        // Tab reachability lives in the focus-cycle tests; park here
        // directly so this test pins scrolling, not tab order. Start
        // from a known offset: the follow-on-select already scrolled to
        // the row's finding.
        app.focus = Focus::Anomalies;
        app.anomalies_offset.set(0);
        // Single-line scroll keys.
        app.handle_key(&plain(KeyCode::Char('j')));
        assert_eq!(app.anomalies_offset.get(), 1);
        app.handle_key(&plain(KeyCode::Down));
        assert_eq!(app.anomalies_offset.get(), 2);
        app.handle_key(&plain(KeyCode::Char('k')));
        assert_eq!(app.anomalies_offset.get(), 1);
        app.handle_key(&plain(KeyCode::Up));
        assert_eq!(app.anomalies_offset.get(), 0);
        // Viewportful paging keys.
        app.anomalies_viewport.set(5);
        app.handle_key(&plain(KeyCode::PageDown));
        assert_eq!(app.anomalies_offset.get(), 5);
        app.handle_key(&plain(KeyCode::Char('f')));
        assert_eq!(app.anomalies_offset.get(), 10);
        app.handle_key(&plain(KeyCode::PageUp));
        assert_eq!(app.anomalies_offset.get(), 5);
        app.handle_key(&plain(KeyCode::Char('b')));
        assert_eq!(app.anomalies_offset.get(), 0);
        app.handle_key(&plain(KeyCode::Char(' ')));
        assert_eq!(app.anomalies_offset.get(), 5);
        app.handle_key(&plain(KeyCode::End));
        assert!(app.anomalies_offset.get() > 1000);
        app.handle_key(&plain(KeyCode::Home));
        assert_eq!(app.anomalies_offset.get(), 0);
    }

    /// Layout budget for the right stack: every pane keeps at least 10%
    /// and leaves at least 10% for the hex pane.
    fn assert_shares(app: &App) {
        assert!(app.answers_pct >= 10, "answers: {}", app.answers_pct);
        assert!(app.questions_pct >= 10, "questions: {}", app.questions_pct);
        assert!(app.anomalies_pct >= 10, "anomalies: {}", app.anomalies_pct);
        assert!(
            app.answers_pct + app.questions_pct + app.anomalies_pct <= 90,
            "hex keeps >= 10: {}+{}+{}",
            app.answers_pct,
            app.questions_pct,
            app.anomalies_pct
        );
    }

    /// Lower-pane rect and moved share for a horizontal divider, by
    /// mode: one dispatch shared by seam lookup and share reads.
    fn seam_target(app: &App, mode: DragMode) -> (ratatui::layout::Rect, u16) {
        match mode {
            DragMode::HorizUpper => (app.questions_rect.get(), app.answers_pct),
            DragMode::HorizMiddle => (app.anomalies_rect.get(), app.questions_pct),
            _ => (app.hex_rect.get(), app.anomalies_pct),
        }
    }

    #[test]
    fn mouse_down_drag_sequence_moves_seams() {
        use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        let mut app = App::new().unwrap();
        let down = |column, row| MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::empty(),
        };
        let drag = |column, row| MouseEvent {
            kind: MouseEventKind::Drag(MouseButton::Left),
            column,
            row,
            modifiers: KeyModifiers::empty(),
        };
        let up = || MouseEvent {
            kind: MouseEventKind::Up(MouseButton::Left),
            column: 40,
            row: 20,
            modifiers: KeyModifiers::empty(),
        };
        // Seams come from the computed layout: the top border row of
        // the lower pane is always a grab zone.
        for mode in [
            DragMode::HorizUpper,
            DragMode::HorizMiddle,
            DragMode::HorizLower,
        ] {
            app.answers_pct = 30;
            app.questions_pct = 25;
            app.anomalies_pct = 20;
            render_to_buffer(&app, 100, 40);
            let (lower, before) = seam_target(&app, mode);
            assert!(lower.height > 2, "pane needs a grabbable border");
            app.handle_mouse(&down(lower.x + 5, lower.y));
            assert_eq!(app.drag, mode);
            app.handle_mouse(&drag(lower.x + 5, lower.y + 6));
            assert!(
                seam_target(&app, mode).1 > before,
                "{mode:?} drag must grow its share"
            );
            app.handle_mouse(&up());
            assert_eq!(app.drag, DragMode::None);
            assert_shares(&app);
        }
        // Extremes through the mouse path: clamps hold and neighbors
        // keep their minimums.
        app.answers_pct = 30;
        app.questions_pct = 25;
        app.anomalies_pct = 20;
        render_to_buffer(&app, 100, 40);
        let right = app.right_rect.get();
        let bottom = right.y + right.height - 1;
        // Lower seam slammed to the bottom: anomalies pins at its max.
        let (hex_top, _) = seam_target(&app, DragMode::HorizLower);
        app.handle_mouse(&down(hex_top.x + 5, hex_top.y));
        assert_eq!(app.drag, DragMode::HorizLower);
        app.handle_mouse(&drag(hex_top.x + 5, bottom));
        assert_eq!(app.drag, DragMode::HorizLower);
        assert_eq!(app.anomalies_pct, 35);
        assert_eq!((app.answers_pct, app.questions_pct), (30, 25));
        // Upper seam slammed to the top: answers pins at 10%.
        let (questions_top, _) = seam_target(&app, DragMode::HorizUpper);
        app.handle_mouse(&down(questions_top.x + 5, questions_top.y));
        assert_eq!(app.drag, DragMode::HorizUpper);
        app.handle_mouse(&drag(questions_top.x + 5, right.y));
        assert_eq!(app.answers_pct, 10);
        assert_shares(&app);
    }

    #[test]
    fn pane_shares_keep_minimums_at_extremes() {
        use ratatui::layout::Rect;
        let mut app = App::new().unwrap();
        app.body_rect.set(Rect::new(0, 3, 100, 40));
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        // Slam every divider against the bottom, then the top.
        app.questions_pct = 25;
        app.anomalies_pct = 20;
        app.set_answers_from_y(3 + 30);
        assert_shares(&app);
        app.answers_pct = 30;
        app.anomalies_pct = 20;
        app.set_middle_from_y(3 + 30);
        assert_shares(&app);
        app.answers_pct = 30;
        app.questions_pct = 25;
        app.set_lower_from_y(3 + 30);
        assert_shares(&app);
        app.set_answers_from_y(3);
        assert_shares(&app);
        assert_eq!(app.answers_pct, 10);
        // The clamped model still renders every pane at normal and
        // small sizes: no share collapses to zero rows.
        for (width, height) in [(100, 30), (60, 12)] {
            render_to_buffer(&app, width, height);
            for pane in [
                &app.answers_rect,
                &app.questions_rect,
                &app.anomalies_rect,
                &app.hex_rect,
            ] {
                assert!(
                    pane.get().height >= 1,
                    "{width}x{height}: slammed shares must still render every pane"
                );
            }
        }
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

    #[test]
    fn tiny_terminal_renders_anomalies_pane() {
        let app = two_group_app();
        for (width, height) in [(100, 30), (60, 12), (40, 8)] {
            let buf = render_to_buffer(&app, width, height);
            // Every right-stack pane keeps a visible row and shows its
            // own title inside its own rect — not just somewhere in the
            // buffer.
            for (rect, title) in [
                (&app.answers_rect, "Answers"),
                (&app.questions_rect, "Questions"),
                (&app.anomalies_rect, "Anomalies"),
                (&app.hex_rect, "Raw Packet"),
            ] {
                let area = rect.get();
                assert!(area.height >= 1, "{width}x{height}: every pane keeps a row");
                assert!(
                    rect_text(&buf, area).contains(title),
                    "{width}x{height} must show the {title} pane in place"
                );
            }
        }
    }

    #[test]
    fn synthetic_rows_and_hostnames_render_italic() {
        use ratatui::style::Modifier;
        let app = two_group_app();
        let buf = render_to_buffer(&app, 100, 30);
        // Host group header: the display name after the glyph is italic,
        // the count and addresses are not.
        let area = app.left_rect.get();
        let mut header = None;
        for y in (area.y + 1)..(area.y + area.height.saturating_sub(1)) {
            let mut row = String::new();
            for x in (area.x + 1)..(area.x + area.width.saturating_sub(1)) {
                row.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or_default());
            }
            if row.starts_with("\u{25be} ") || row.starts_with("\u{25b8} ") {
                header = Some((y, row));
                break;
            }
        }
        let (y, row) = header.expect("host header row");
        let name_cell = buf.cell((area.x + 3, y)).expect("display-name cell");
        assert!(
            name_cell.modifier.contains(Modifier::ITALIC),
            "hostname should be italic"
        );
        let paren = row.rfind(" (").expect("header count");
        let count_cell = buf
            .cell((area.x + 1 + paren as u16 + 1, y))
            .expect("count cell");
        assert!(
            !count_cell.modifier.contains(Modifier::ITALIC),
            "only the hostname is italic"
        );
        // Detail table synthetic rows (`srvc`, …) are italic throughout.
        let area = app.answers_rect.get();
        let label_cell = buf.cell((area.x + 1, area.y + 2)).expect("srvc cell");
        assert_eq!(label_cell.symbol(), "s");
        assert!(
            label_cell.modifier.contains(Modifier::ITALIC),
            "synthetic rows should be italic"
        );
    }

    #[test]
    fn txt_children_render_upright() {
        use crossterm::event::{KeyCode, KeyEventKind, KeyEventState, KeyModifiers};
        use ratatui::style::Modifier;
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "a=1; b=2");
        let key = |code| KeyEvent {
            code,
            modifiers: KeyModifiers::empty(),
            kind: KeyEventKind::Press,
            state: KeyEventState::empty(),
        };
        app.handle_key(&key(KeyCode::Tab));
        app.handle_key(&key(KeyCode::Enter));
        let buf = render_to_buffer(&app, 100, 30);
        let area = app.answers_rect.get();
        // Expanded TXT pair rows show verbatim wire content: green like
        // the header rows, but never italic.
        let mut pair = None;
        for y in (area.y + 1)..(area.y + area.height.saturating_sub(1)) {
            let mut row = String::new();
            for x in (area.x + 1)..(area.x + area.width.saturating_sub(1)) {
                row.push_str(buf.cell((x, y)).map(|c| c.symbol()).unwrap_or_default());
            }
            if (row.contains("├─") || row.contains("└─")) && row.contains("a=1") {
                pair = Some((y, row));
                break;
            }
        }
        let (y, _) = pair.expect("expanded TXT pair row");
        let cell = buf.cell((area.x + 1, y)).expect("pair cell");
        assert!(
            !cell.modifier.contains(Modifier::ITALIC),
            "wire content stays upright"
        );
        assert_eq!(
            cell.fg,
            ratatui::style::Color::Green,
            "pair rows keep the info color, got: {:?}",
            cell.fg
        );
    }

    #[test]
    fn mouse_border_hit_test_prefers_seams() {
        use ratatui::layout::Rect;
        let app = App::new().unwrap();
        // Abutting panes: the two border cells form the grab zone.
        app.left_rect.set(Rect::new(0, 3, 33, 30));
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        app.answers_rect.set(Rect::new(33, 3, 67, 10));
        app.questions_rect.set(Rect::new(33, 13, 67, 8));
        app.anomalies_rect.set(Rect::new(33, 21, 67, 6));
        app.hex_rect.set(Rect::new(33, 27, 67, 6));
        // Either border cell grabs vertically.
        assert_eq!(app.divider_at(32, 5), DragMode::Vertical);
        assert_eq!(app.divider_at(33, 5), DragMode::Vertical);
        // Either border row grabs horizontally.
        assert_eq!(app.divider_at(40, 12), DragMode::HorizUpper);
        assert_eq!(app.divider_at(40, 13), DragMode::HorizUpper);
        assert_eq!(app.divider_at(40, 20), DragMode::HorizMiddle);
        assert_eq!(app.divider_at(40, 21), DragMode::HorizMiddle);
        assert_eq!(app.divider_at(40, 26), DragMode::HorizLower);
        assert_eq!(app.divider_at(40, 27), DragMode::HorizLower);
        // Interior cells belong to panes.
        assert_eq!(app.divider_at(10, 5), DragMode::None);
        assert_eq!(app.divider_at(40, 5), DragMode::None);
    }

    #[test]
    fn anomalies_pane_lists_service_findings_with_cursor_match() {
        let mut app = App::new().unwrap();
        // Quiet 4500s base so the PTR row's only finding is the
        // shared-flush error from the set bit below.
        let mut ptr = ptr_record(4500);
        ptr.flush_bit = true;
        ingest(&mut app, &ptr);
        ingest(&mut app, &srv_record(120));
        app.evict_expired();
        select_instance(&mut app, "Test");
        // Park the cursor on the PTR row: the pane lists the whole
        // service, marking only the row's own finding.
        let ptr_idx = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .position(|r| r.rtype == 12)
            .expect("PTR row");
        app.detail_selected = ptr_idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, ptr_idx));
        let found = app.anomalies_for_selected();
        assert_eq!(
            kinds(&found),
            ["shared-flush"],
            "pane lists the full service, got: {found:?}"
        );
        assert_eq!(matched(&found), ["shared-flush"]);
        // The healthy SRV row sees the same list with nothing marked
        // (its missing flush bit is info-only, excluded).
        let srv_idx = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .position(|r| r.rtype == 33)
            .expect("SRV row");
        app.detail_selected = srv_idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, srv_idx));
        let found = app.anomalies_for_selected();
        assert_eq!(kinds(&found), ["shared-flush"]);
        assert!(
            matched(&found).is_empty(),
            "healthy row marks nothing, got: {found:?}"
        );
    }

    #[test]
    fn anomalies_pane_marks_ttl_base_mismatch_in_list() {
        let mut app = App::new().unwrap();
        // The pane excludes informational findings; the full set still
        // holds the informational base-mismatch.
        ingest(&mut app, &ptr_record(120));
        ingest(&mut app, &srv_record(120));
        app.evict_expired();
        select_instance(&mut app, "Test");
        let ptr_idx = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .position(|r| r.rtype == 12)
            .expect("PTR row");
        app.detail_selected = ptr_idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, ptr_idx));
        let found = app.anomalies_for_selected();
        assert!(found.is_empty(), "pane hides informational findings");
        let all = app.anomalies();
        let base = all
            .iter()
            .find(|a| a.kind == anomalies::AnomalyKind::TtlMismatch)
            .expect("base mismatch still analyzed");
        assert_eq!(
            base.severity,
            crate::anomalies::Severity::Info,
            "base mismatch is Info, got: {base:?}"
        );
        assert!(
            found.iter().all(|p| p.anomaly.is_surfaced()),
            "pane never shows informational notes"
        );
    }

    #[test]
    fn anomalies_for_selected_empty_for_expired_rows() {
        let mut app = App::new().unwrap();
        let mut ptr = ptr_record(4500);
        ptr.flush_bit = true;
        ingest(&mut app, &ptr);
        ingest(&mut app, &srv_record(120));
        app.evict_expired();
        select_instance(&mut app, "Test");
        // Age the PTR past its TTL: the expired row reports nothing.
        expire_rtype(&mut app, 12, 5000);
        let ptr_idx = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .position(|r| r.rtype == 12)
            .expect("PTR row");
        app.detail_selected = ptr_idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, ptr_idx));
        assert!(app.anomalies_for_selected().is_empty());
    }

    #[test]
    fn anomalies_for_selected_spans_ttl_unstable_rows() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        // Same name and type, different TTL bases: one spanning finding.
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.11", 4500),
        );
        app.evict_expired();
        select_instance(&mut app, "Test");
        let a_rows: Vec<usize> = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .enumerate()
            .filter(|(_, r)| r.rtype == 1)
            .map(|(i, _)| i)
            .collect();
        assert_eq!(a_rows.len(), 2);
        for idx in a_rows {
            app.detail_selected = idx;
            app.detail_anchor = app
                .display_detail()
                .and_then(|d| App::identity_at_detail(&d, idx));
            let found = app.anomalies_for_selected();
            assert_eq!(
                kinds(&found),
                ["ttl-unstable"],
                "pane lists the full service, got: {found:?}"
            );
            assert_eq!(
                matched(&found),
                ["ttl-unstable"],
                "A row {idx} must mark the spanning finding"
            );
            assert_eq!(
                found[0].anomaly.rtype_str.as_deref(),
                Some("A"),
                "spanning finding keeps its type label, got: {found:?}"
            );
        }
    }

    #[test]
    fn anomalies_for_question_keeps_info_findings_out_of_pane() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        let src_a = remote_source();
        let src_b: SocketAddr = "192.168.1.100:5353".parse().unwrap();
        // Two queriers ask multicast for NS: RFC 6762 §3 makes that
        // compliant, so the info-level findings stay in the overlay and
        // no question row lists or marks anything.
        app.ingest_event(&query_event(
            "test.local.",
            2,
            "NS",
            false,
            Vec::new(),
            src_a,
        ));
        app.ingest_event(&query_event(
            "test.local.",
            2,
            "NS",
            false,
            Vec::new(),
            src_b,
        ));
        // Our own inferred send for a multicast type stays quiet.
        app.route_own_question("test.local", 1, false);
        app.evict_expired();
        select_instance(&mut app, "Test");
        let raws = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .len();
        assert_eq!(
            app.anomalies()
                .iter()
                .filter(|a| a.kind == anomalies::AnomalyKind::UnicastQuestion)
                .count(),
            2,
            "one info finding per querier"
        );
        for src in [src_a, src_b, crate::app::SELF_SOURCE] {
            let pos = app
                .display_detail()
                .expect("service displayed")
                .ordered_questions()
                .iter()
                .position(|q| q.2 == src)
                .unwrap_or_else(|| panic!("question row for {src}"));
            let idx = raws + pos;
            app.detail_selected = idx;
            app.detail_anchor = app
                .display_detail()
                .and_then(|d| App::identity_at_detail(&d, idx));
            let found = app.anomalies_for_selected();
            assert!(
                found.is_empty(),
                "row for {src} lists no info findings, got: {found:?}"
            );
        }
    }

    /// Park the left selection on a collapsed host header: scope and
    /// cursor stay service-wide, with nothing marked.
    fn select_host_header(app: &mut App, key: &str) {
        app.collapsed_hosts.insert(key.to_string());
        let pos = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Host { label } if label == key))
            .unwrap_or_else(|| panic!("host header for {key}"));
        app.selected_display = pos;
        app.clamp_selection();
        assert!(app.selected_service().is_none());
        assert!(app.anomalies_show_service_level());
    }

    #[test]
    fn anomalies_for_header_shows_service_level() {
        let mut app = App::new().unwrap();
        // An unqueried target does not establish a resolution failure.
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        app.evict_expired();
        select_instance(&mut app, "Test");
        select_host_header(&mut app, "test.local");
        let found = app.anomalies_for_selected();
        assert!(found.is_empty(), "no address queries were transmitted");
        assert!(
            matched(&found).is_empty(),
            "header marks nothing, got: {found:?}"
        );
    }

    #[test]
    fn omitted_additional_addresses_do_not_report_an_anomaly() {
        let mut app = App::new().unwrap();
        let ptr = ptr_record(4500);
        let mut srv = srv_record(120);
        srv.section = browse::RecordSection::Additional;
        let mut event = event_for(&ptr);
        event.answers = vec![ptr, srv];
        ingest_packet(&mut app, event);

        assert!(app.anomalies().is_empty());

        // Resolving the target through a later query is normal, too.
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        ingest_packet(
            &mut app,
            event_for(&raw_record("test.local.", 1, "A", "192.168.1.10", 120)),
        );
        assert!(app.anomalies().is_empty());
    }

    #[test]
    fn unanswered_address_queries_are_inconclusive() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));

        let findings = app.anomalies();
        let finding = findings
            .iter()
            .find(|a| a.kind.as_str() == "unresolved-srv-target")
            .unwrap_or_else(|| panic!("expected an address-query outcome: {findings:?}"));
        assert_eq!(finding.severity, anomalies::Severity::Info);
        assert!(finding.message.contains("A: no response"));
        assert!(finding.message.contains("AAAA: no response"));
        assert!(finding.message.contains("inconclusive"));
        assert!(!finding.message.contains("NODATA"));
        assert!(!finding.message.contains("NXDOMAIN"));
    }

    #[test]
    fn empty_mdns_response_is_inconclusive_not_a_timeout_or_nodata() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        ingest_packet(
            &mut app,
            browse::Event {
                answers: Vec::new(),
                questions: Vec::new(),
                query_kas: Vec::new(),
                rcode: Some(0),
                received_at: Instant::now(),
                raw_bytes: Vec::new(),
                source: test_source(),
            },
        );

        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind.as_str() == "unresolved-srv-target")
            .expect("expected an inconclusive address-query outcome");
        assert_eq!(finding.severity, anomalies::Severity::Info);
        assert!(finding.message.contains("unattributed mDNS response"));
        assert!(!finding.message.contains("no response"));
        assert!(!finding.message.contains("NODATA"));
    }

    #[test]
    fn address_queries_remain_pending_during_the_response_window() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::ZERO);

        assert!(!app
            .anomalies()
            .iter()
            .any(|a| a.kind.as_str() == "unresolved-srv-target"));
    }

    #[test]
    fn explicit_nsec_negative_answers_are_distinguished_from_silence() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        let mut nsec = raw_record("test.local.", 47, "NSEC", "test.local. PTR SRV", 120);
        nsec.iface = "br0".to_string();
        ingest_packet(
            &mut app,
            browse::Event {
                answers: vec![nsec],
                questions: Vec::new(),
                query_kas: Vec::new(),
                rcode: Some(0),
                received_at: Instant::now(),
                raw_bytes: Vec::new(),
                source: test_source(),
            },
        );
        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind.as_str() == "unresolved-srv-target")
            .expect("expected an address-query outcome");
        assert_eq!(
            finding.severity,
            anomalies::Severity::Warning,
            "{finding:?}"
        );
        assert!(finding.message.contains("A: NODATA"));
        assert!(finding.message.contains("AAAA: NODATA"));
        assert!(finding.message.contains("br0"));
        assert!(!finding.message.contains("inconclusive"));
    }

    #[test]
    fn one_nodata_family_does_not_prove_the_srv_target_unresolvable() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        let nsec = raw_record("test.local.", 47, "NSEC", "test.local. AAAA PTR SRV", 120);
        ingest_packet(
            &mut app,
            browse::Event {
                answers: vec![nsec],
                questions: Vec::new(),
                query_kas: Vec::new(),
                rcode: Some(0),
                received_at: Instant::now(),
                raw_bytes: Vec::new(),
                source: test_source(),
            },
        );

        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind.as_str() == "unresolved-srv-target")
            .expect("expected an address-query outcome");
        assert_eq!(finding.severity, anomalies::Severity::Info);
        assert!(finding.message.contains("A: NODATA"));
        assert!(finding.message.contains("AAAA: unattributed mDNS response"));
        assert!(finding.message.contains("inconclusive"));
    }

    #[test]
    fn one_observed_address_family_resolves_the_srv_target() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        ingest(
            &mut app,
            &raw_record("test.local.", 28, "AAAA", "fe80::1", 120),
        );

        assert!(!app
            .anomalies()
            .iter()
            .any(|a| a.kind.as_str() == "unresolved-srv-target"));
    }

    #[test]
    fn expired_selected_target_does_not_report_against_a_live_alternate() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        let mut alternate = srv_record(120);
        alternate.rdata = "0 0 80 backup.local.".to_string();
        ingest(&mut app, &alternate);

        let expired_at = Instant::now() - Duration::from_secs(2);
        for rec in &mut app.services[0].answers {
            if rec.rtype == 33 && rec.rdata.ends_with("backup.local.") {
                rec.ttl = 1;
                rec.received_at = expired_at;
            }
        }
        mark_address_queries(&mut app, "backup.local", Duration::from_secs(2));

        assert!(!app
            .anomalies()
            .iter()
            .any(|a| a.kind.as_str() == "unresolved-srv-target"));
    }

    #[test]
    fn non_local_srv_target_is_scoped_to_mdns_observation() {
        let mut app = App::new().unwrap();
        ingest(
            &mut app,
            &raw_record(
                "_avmnexus._tcp.local.",
                12,
                "PTR",
                "Fritzel._avmnexus._tcp.local.",
                4500,
            ),
        );
        ingest(
            &mut app,
            &raw_record(
                "Fritzel._avmnexus._tcp.local.",
                33,
                "SRV",
                "0 0 80 fritz.box.",
                120,
            ),
        );
        mark_address_queries(&mut app, "fritz.box", Duration::from_secs(2));

        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| {
                a.kind.as_str() == "unresolved-srv-target"
                    && a.service == "Fritzel._avmnexus._tcp.local"
            })
            .expect("expected mDNS address-query outcome");
        assert_eq!(finding.severity, anomalies::Severity::Info);
        assert!(finding.message.contains("fritz.box"));
        assert!(finding.message.contains("unicast DNS may still resolve"));
    }

    #[test]
    fn unassociated_nxdomain_response_is_not_attributed_to_srv_target() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        ingest_packet(
            &mut app,
            browse::Event {
                answers: Vec::new(),
                questions: Vec::new(),
                query_kas: Vec::new(),
                rcode: Some(3),
                received_at: Instant::now(),
                raw_bytes: Vec::new(),
                source: test_source(),
            },
        );

        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind.as_str() == "unresolved-srv-target")
            .expect("expected an inconclusive address-query outcome");
        assert_eq!(finding.severity, anomalies::Severity::Info);
        assert!(finding.message.contains("unattributed NXDOMAIN response"));
        assert!(finding.message.contains("inconclusive"));
        assert!(!finding.message.contains("A: NXDOMAIN"));
    }

    #[test]
    fn name_attributed_nxdomain_is_reported_as_explicit_negative() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        let cname = raw_record("test.local.", 5, "CNAME", "missing.local.", 120);
        ingest_packet(
            &mut app,
            browse::Event {
                answers: vec![cname],
                questions: Vec::new(),
                query_kas: Vec::new(),
                rcode: Some(3),
                received_at: Instant::now(),
                raw_bytes: Vec::new(),
                source: test_source(),
            },
        );

        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind.as_str() == "unresolved-srv-target")
            .expect("expected an address-query outcome");
        assert_eq!(finding.severity, anomalies::Severity::Warning);
        assert!(finding.message.contains("A: NXDOMAIN"));
        assert!(finding.message.contains("AAAA: NXDOMAIN"));
    }

    #[test]
    fn additional_cname_does_not_attribute_nxdomain_to_srv_target() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        let mut cname = raw_record("test.local.", 5, "CNAME", "missing.local.", 120);
        cname.section = browse::RecordSection::Additional;
        ingest_packet(
            &mut app,
            browse::Event {
                answers: vec![cname],
                questions: Vec::new(),
                query_kas: Vec::new(),
                rcode: Some(3),
                received_at: Instant::now(),
                raw_bytes: Vec::new(),
                source: test_source(),
            },
        );

        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind.as_str() == "unresolved-srv-target")
            .expect("expected an inconclusive address-query outcome");
        assert_eq!(finding.severity, anomalies::Severity::Info);
        assert!(finding.message.contains("unattributed NXDOMAIN response"));
        assert!(!finding.message.contains("A: NXDOMAIN"));
    }

    #[test]
    fn expired_address_preserves_response_evidence_without_resolving_target() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(10));
        let mut addr = raw_record("test.local.", 1, "A", "192.168.1.10", 1);
        addr.received_at = Instant::now() - Duration::from_secs(5);
        ingest(&mut app, &addr);
        let found = app.anomalies();
        let finding = found
            .iter()
            .find(|a| a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget)
            .unwrap();
        assert!(finding.message.contains("answered; address expired"));
        assert_eq!(finding.severity, anomalies::Severity::Info);
    }

    #[test]
    fn negative_families_on_different_interfaces_do_not_combine() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        for state in app.query_history.values_mut() {
            state.transmitted_interfaces = "br0, eth0".into();
        }
        for (iface, bitmap) in [("br0", "AAAA"), ("eth0", "A")] {
            let mut nsec = raw_record(
                "test.local.",
                47,
                "NSEC",
                &format!("test.local. {bitmap}"),
                120,
            );
            nsec.iface = iface.into();
            ingest_packet(&mut app, event_for(&nsec));
        }
        let found: Vec<_> = app
            .anomalies()
            .into_iter()
            .filter(|a| a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget)
            .collect();
        assert_eq!(found.len(), 2);
        assert!(found
            .iter()
            .all(|a| a.severity == anomalies::Severity::Info));
        assert!(found.iter().any(|a| a.message.contains("interfaces br0")));
        assert!(found.iter().any(|a| a.message.contains("interfaces eth0")));
    }

    #[test]
    fn unrelated_response_does_not_turn_silence_into_inconclusive_response() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        ingest_packet(
            &mut app,
            event_for(&raw_record("other.local.", 1, "A", "192.168.1.10", 120)),
        );
        let finding = app
            .anomalies()
            .into_iter()
            .find(|a| a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget)
            .unwrap();
        assert!(finding.message.contains("A: no response"));
        assert!(finding.message.contains("AAAA: no response"));
    }

    #[test]
    fn query_interfaces_survive_link_changes_and_exclude_inactive_selection() {
        let mut app = App::new().unwrap();
        app.interfaces = Some(
            ["br0".to_string(), "down0".to_string()]
                .into_iter()
                .collect(),
        );
        app.link_stats.v4 = vec![("br0".into(), "192.168.1.2".parse().unwrap())];
        app.link_stats.v6.clear();
        app.note_query("test.local", 1, QueryOrigin::Transmitted, Instant::now());
        app.link_stats.v4.clear();
        app.interfaces = None;
        assert_eq!(
            app.query_history[&App::provenance_key("test.local", 1)].transmitted_interfaces,
            "br0"
        );
    }

    #[test]
    fn queried_srv_target_is_analyzed_when_another_host_is_displayed() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        mark_address_queries(&mut app, "test.local", Duration::from_secs(2));
        app.services[0].hostname = "display.local".into();
        assert!(app
            .anomalies()
            .iter()
            .any(|a| a.kind == anomalies::AnomalyKind::UnresolvedSrvTarget
                && a.message.contains("test.local")));
    }

    #[test]
    fn anomalies_for_header_shows_spanning_ttl_unstable() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.11", 4500),
        );
        app.evict_expired();
        select_instance(&mut app, "Test");
        select_host_header(&mut app, "test.local");
        let found = app.anomalies_for_selected();
        assert_eq!(
            kinds(&found),
            ["ttl-unstable"],
            "header shows the service list, got: {found:?}"
        );
        assert!(
            matched(&found).is_empty(),
            "header marks nothing, got: {found:?}"
        );
    }

    #[test]
    fn anomalies_for_header_shows_enum_type_format() {
        let mut app = App::new().unwrap();
        // Malformed enumerated type: the finding carries the PTR row's
        // identity (so the row marks) but describes the enumeration.
        ingest(
            &mut app,
            &raw_record(
                "_services._dns-sd._udp.local.",
                12,
                "PTR",
                "badtype.local.",
                4500,
            ),
        );
        app.evict_expired();
        // Select the enumeration row to make it sticky, then rest on its
        // header: the header is the finding's service-level home.
        let enum_pos = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Enum { .. }))
            .expect("enum row");
        app.selected_display = enum_pos;
        app.clamp_selection();
        assert!(app.selected_enum().is_some());
        select_host_header(&mut app, ENUM_HOST);
        let found = app.anomalies_for_selected();
        assert_eq!(
            kinds(&found),
            ["type-format"],
            "enum header shows the service list, got: {found:?}"
        );
        assert!(
            matched(&found).is_empty(),
            "header marks nothing, got: {found:?}"
        );
        // The row itself marks the finding too: expand the group again
        // and park on the record row (the collapsed header index would
        // not restore it).
        app.collapsed_hosts.remove(ENUM_HOST);
        let enum_pos = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Enum { .. }))
            .expect("enum row");
        app.selected_display = enum_pos;
        app.clamp_selection();
        assert!(matches!(
            app.anomaly_scope(),
            crate::app::AnomalyScope::Record(_)
        ));
        let found = app.anomalies_for_selected();
        assert_eq!(kinds(&found), ["type-format"]);
        assert_eq!(matched(&found), ["type-format"]);
    }

    /// Park the detail cursor on a raw-answer row and return the pane
    /// entries shown there.
    fn park_on(app: &mut App, idx: usize) -> Vec<PaneAnomaly> {
        app.detail_selected = idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, idx));
        app.anomalies_for_selected()
    }

    /// Finding kinds in pane order.
    fn kinds(found: &[PaneAnomaly]) -> Vec<&'static str> {
        found.iter().map(|p| p.anomaly.kind.as_str()).collect()
    }

    /// Kinds of the entries marked as the cursor's own finding.
    fn matched(found: &[PaneAnomaly]) -> Vec<&'static str> {
        found
            .iter()
            .filter(|p| p.cursor_match)
            .map(|p| p.anomaly.kind.as_str())
            .collect()
    }

    /// Park the detail cursor on the raw-answer row with this identity
    /// and return the pane entries shown there.
    fn park_on_answer(app: &mut App, rtype: u16, rdata: &str) -> Vec<PaneAnomaly> {
        let idx = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .position(|r| r.rtype == rtype && r.rdata == rdata)
            .unwrap_or_else(|| panic!("row for {rdata}"));
        park_on(app, idx)
    }

    /// Park the detail cursor on the question row from this source and
    /// return the pane entries shown there.
    fn park_on_question(app: &mut App, source: SocketAddr) -> Vec<PaneAnomaly> {
        let target = app.display_detail().expect("service displayed");
        let pos = target
            .ordered_questions()
            .iter()
            .position(|q| q.2 == source)
            .unwrap_or_else(|| panic!("question row for {source}"));
        park_on(app, target.ordered_answers().len() + pos)
    }

    /// Age every answer of this type past its TTL, turning live rows
    /// into expired ones.
    fn expire_rtype(app: &mut App, rtype: u16, secs: u64) {
        for svc in &mut app.services {
            for rec in &mut svc.answers {
                if rec.rtype == rtype {
                    rec.received_at = Instant::now()
                        .checked_sub(Duration::from_secs(secs))
                        .unwrap_or_else(Instant::now);
                }
            }
        }
    }

    #[test]
    fn anomalies_pane_never_shows_stale_findings() {
        let mut app = App::new().unwrap();
        let mut ptr = ptr_record(4500);
        ptr.flush_bit = true;
        ingest(&mut app, &ptr);
        ingest(&mut app, &srv_record(120));
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.11", 4500),
        );
        let querier: SocketAddr = "192.168.1.9:5353".parse().unwrap();
        app.ingest_event(&query_event(
            "test.local.",
            2,
            "NS",
            false,
            Vec::new(),
            querier,
        ));
        app.evict_expired();
        select_instance(&mut app, "Test");
        // Every stop shows the full service list with only its own
        // findings marked: nothing leaks from the previously
        // highlighted row.
        // The NS question is info-level (RFC 6762 §3 makes asking
        // compliant), so it stays out of the pane.
        let full = ["shared-flush", "ttl-unstable"];
        let stop = |found: Vec<PaneAnomaly>, marked: &[&str]| {
            assert_eq!(
                kinds(&found),
                full,
                "pane lists the full service, got: {found:?}"
            );
            assert_eq!(matched(&found), marked);
        };
        stop(
            park_on_answer(&mut app, 12, "Test._http._tcp.local."),
            &["shared-flush"],
        );
        stop(park_on_answer(&mut app, 33, "0 0 80 test.local."), &[]);
        stop(
            park_on_answer(&mut app, 1, "192.168.1.10"),
            &["ttl-unstable"],
        );
        stop(
            park_on_answer(&mut app, 1, "192.168.1.11"),
            &["ttl-unstable"],
        );
        stop(park_on_question(&mut app, querier), &[]);
        select_host_header(&mut app, "test.local");
        stop(app.anomalies_for_selected(), &[]);
        // Expire the PTR: its row goes quiet instead of keeping the
        // shared-flush finding it showed while live.
        expire_rtype(&mut app, 12, 5000);
        // Back on the instance row: the gone row names its state.
        app.collapsed_hosts.remove("test.local");
        select_instance(&mut app, "Test");
        assert!(park_on_answer(&mut app, 12, "Test._http._tcp.local.").is_empty());
    }

    #[test]
    fn anomalies_pane_follows_cursor_to_match() {
        let mut app = App::new().unwrap();
        let mut ptr = ptr_record(4500);
        ptr.flush_bit = true;
        ingest(&mut app, &ptr);
        ingest(&mut app, &srv_record(120));
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.11", 4500),
        );
        app.evict_expired();
        select_instance(&mut app, "Test");
        // Cursor starts on the first A row, whose finding is second in
        // the pane: follow scrolls there, not to the top.
        assert_eq!(app.anomalies_offset.get(), 1);
        app.focus = Focus::Answers;
        app.move_detail_cursor(1);
        assert_eq!(app.detail_selected, 1);
        assert_eq!(app.anomalies_offset.get(), 1);
        app.move_detail_cursor(1);
        assert_eq!(app.detail_selected, 2);
        assert_eq!(app.anomalies_offset.get(), 0);
        // Header: a manual scroll resets on selection instead of
        // lingering mid-list with nothing marked.
        app.scroll_anomalies(3);
        select_host_header(&mut app, "test.local");
        assert_eq!(app.anomalies_offset.get(), 0);
    }

    #[test]
    fn tracked_offset_follows_match_and_yields_to_manual() {
        assert_eq!(App::tracked_anomalies_offset(true, 0, Some(2), 5), 2);
        assert_eq!(App::tracked_anomalies_offset(true, 5, Some(5), 6), 5);
        assert_eq!(App::tracked_anomalies_offset(true, 5, None, 3), 0);
        assert_eq!(App::tracked_anomalies_offset(true, 0, None, 1), 0);
        assert_eq!(App::tracked_anomalies_offset(false, 4, Some(1), 5), 4);
        assert_eq!(App::tracked_anomalies_offset(false, 0, None, 1), 0);
    }

    #[test]
    fn anomalies_pane_tracks_list_changes_until_manual_scroll() {
        let mut app = App::new().unwrap();
        let mut ptr = ptr_record(4500);
        ptr.flush_bit = true;
        ingest(&mut app, &ptr);
        ingest(&mut app, &srv_record(120));
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.10", 120),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.11", 4500),
        );
        app.evict_expired();
        select_instance(&mut app, "Test");
        // Cursor on an A row, marked second: [shared-flush, ttl-unstable].
        park_on_answer(&mut app, 1, "192.168.1.10");
        // Match index and visible viewport, whatever the layout gives.
        let visible_match = |app: &App| {
            let area = app.anomalies_rect.get();
            let viewport = (area.height.saturating_sub(2) as usize).max(1);
            let offset = app.anomalies_offset.get();
            let found = app.anomalies_for_selected();
            let at = found.iter().position(|p| p.cursor_match);
            (offset, viewport, at)
        };
        render_to_buffer(&app, 100, 30);
        assert!(app.anomalies_follow.get());
        let (offset, viewport, at) = visible_match(&app);
        assert_eq!(at, Some(1));
        assert!(
            (offset..offset + viewport).contains(&1),
            "match must be visible after follow"
        );
        // A new error finding sorts in front without any cursor move:
        // tracking re-anchors to the match instead of hiding it.
        ingest(
            &mut app,
            &raw_record("test.local.", 2, "NS", "ns1.local.", 120),
        );
        render_to_buffer(&app, 100, 30);
        let (offset, viewport, at) = visible_match(&app);
        assert_eq!(at, Some(2));
        assert!(
            (offset..offset + viewport).contains(&2),
            "match must stay visible as the list grows, offset {offset} viewport {viewport}"
        );
        // Manual scroll pauses tracking: the next arrival leaves the
        // viewport where the user put it.
        app.scroll_anomalies(-(offset as isize) - 10);
        assert_eq!(app.anomalies_offset.get(), 0);
        assert!(!app.anomalies_follow.get());
        ingest(
            &mut app,
            &raw_record("test.local.", 2, "NS", "ns2.local.", 120),
        );
        render_to_buffer(&app, 100, 30);
        assert_eq!(app.anomalies_offset.get(), 0);
    }

    #[test]
    fn anomalies_pane_names_gone_rows() {
        let mut app = App::new().unwrap();
        let mut ptr = ptr_record(4500);
        ptr.flush_bit = true;
        ingest(&mut app, &ptr);
        ingest(&mut app, &srv_record(120));
        app.evict_expired();
        select_instance(&mut app, "Test");
        let ptr_idx = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .position(|r| r.rtype == 12)
            .expect("PTR row");
        // Expired rows name their state instead of findings.
        expire_rtype(&mut app, 12, 5000);
        app.detail_selected = ptr_idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, ptr_idx));
        assert!(app.anomalies_for_selected().is_empty());
        let buf = render_to_buffer(&app, 100, 30);
        let text = rect_text(&buf, app.anomalies_rect.get());
        assert!(text.contains("Record expired"), "expired rows must say so");
        assert!(
            text.contains("(0)"),
            "gone rows count zero findings, got: {text:?}"
        );
        // Goodbye rows get their own copy.
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        ingest(&mut app, &ptr_record(0));
        select_instance(&mut app, "Test");
        let ptr_idx = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .position(|r| r.rtype == 12)
            .expect("PTR row");
        app.detail_selected = ptr_idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, ptr_idx));
        assert!(app.anomalies_for_selected().is_empty());
        let buf = render_to_buffer(&app, 100, 30);
        let text = rect_text(&buf, app.anomalies_rect.get());
        assert!(
            text.contains("Goodbye received"),
            "goodbye rows must say so"
        );
        assert!(
            text.contains("(0)"),
            "gone rows count zero findings, got: {text:?}"
        );
    }

    #[test]
    fn anomalies_pane_marks_severity_like_metrics() {
        let mut app = App::new().unwrap();
        // shared-flush is an error: the red level icon carries the
        // severity, so the line spells no severity word.
        let mut ptr = ptr_record(4500);
        ptr.flush_bit = true;
        ingest(&mut app, &ptr);
        ingest(&mut app, &srv_record(120));
        app.evict_expired();
        select_instance(&mut app, "Test");
        let ptr_idx = app
            .display_detail()
            .expect("service displayed")
            .ordered_answers()
            .iter()
            .position(|r| r.rtype == 12)
            .expect("PTR row");
        app.detail_selected = ptr_idx;
        app.detail_anchor = app
            .display_detail()
            .and_then(|d| App::identity_at_detail(&d, ptr_idx));
        let buf = render_to_buffer(&app, 100, 30);
        let area = app.anomalies_rect.get();
        let text = rect_text(&buf, area);
        assert!(
            text.contains("shared-flush"),
            "pane must name the kind, got: {text:?}"
        );
        assert!(
            !text.contains("error shared-flush"),
            "no severity word: the icon carries the level, got: {text:?}"
        );
        assert!(
            text.contains("192.168.1.2:5353: shared-flush"),
            "source leads the finding, got: {text:?}"
        );
        assert!(
            text.contains("> \u{f057}"),
            "cursor row's finding must carry the marker, got: {text:?}"
        );
        assert!(
            text.contains("PTR _http._tcp.local."),
            "line must name its row, got: {text:?}"
        );
        let mut icon_fg = None;
        for y in area.y..area.y.saturating_add(area.height) {
            for x in area.x..area.x.saturating_add(area.width) {
                if let Some(cell) = buf.cell((x, y)) {
                    if cell.symbol() == "\u{f057}" {
                        icon_fg = Some(cell.fg);
                    }
                }
            }
        }
        assert_eq!(
            icon_fg,
            Some(ratatui::style::Color::Red),
            "error icon must match the metrics overlay color"
        );
    }

    #[test]
    fn anomalies_pane_disambiguates_shared_identity() {
        let mut app = App::new().unwrap();
        ingest(&mut app, &ptr_record(4500));
        ingest(&mut app, &srv_record(120));
        // Same name and type, distinct rdata: two findings that share
        // their row identity.
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.10", 5),
        );
        ingest(
            &mut app,
            &raw_record("test.local.", 1, "A", "192.168.1.11", 5),
        );
        app.evict_expired();
        select_instance(&mut app, "Test");
        let found = app.anomalies_for_selected();
        assert_eq!(kinds(&found), ["ttl-low", "ttl-low"]);
        // Park on the second row: only its finding is marked, and the
        // lines name their rdata so the rows tell apart.
        park_on_answer(&mut app, 1, "192.168.1.11");
        let found = app.anomalies_for_selected();
        assert_eq!(matched(&found), ["ttl-low"]);
        assert!(
            found
                .iter()
                .all(|p| p.anomaly.rdata.as_deref() == Some("192.168.1.11") || !p.cursor_match),
            "only the parked row's finding may mark, got: {found:?}"
        );
        let buf = render_to_buffer(&app, 100, 30);
        let text = rect_text(&buf, app.anomalies_rect.get());
        assert!(
            text.contains("A test.local. = 192.168.1.10"),
            "lines must disambiguate shared identities, got: {text:?}"
        );
        assert!(
            text.contains("A test.local. = 192.168.1.11"),
            "lines must disambiguate shared identities, got: {text:?}"
        );
    }

    #[test]
    fn mouse_down_on_border_starts_drag() {
        use crossterm::event::{KeyModifiers, MouseButton, MouseEvent, MouseEventKind};
        use ratatui::layout::Rect;
        let mut app = App::new().unwrap();
        app.body_rect.set(Rect::new(0, 3, 100, 40));
        app.left_rect.set(Rect::new(0, 3, 33, 37));
        app.right_rect.set(Rect::new(33, 3, 67, 37));
        app.answers_rect.set(Rect::new(33, 3, 67, 12));
        app.questions_rect.set(Rect::new(33, 15, 67, 12));
        app.hex_rect.set(Rect::new(33, 27, 67, 13));
        // Right border cell of the Hosts pane starts a vertical drag.
        let down = MouseEvent {
            kind: MouseEventKind::Down(MouseButton::Left),
            column: 32,
            row: 10,
            modifiers: KeyModifiers::empty(),
        };
        app.handle_mouse(&down);
        assert_eq!(app.drag, DragMode::Vertical);
    }

    #[test]
    fn metrics_overlay_suppresses_resize_hover() {
        use crossterm::event::{
            KeyCode, KeyEventKind, KeyEventState, KeyModifiers, MouseButton, MouseEvent,
            MouseEventKind,
        };
        use ratatui::layout::Rect;
        let mut app = App::new().unwrap();
        app.left_rect.set(Rect::new(0, 3, 33, 30));
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        app.answers_rect.set(Rect::new(33, 3, 67, 10));
        app.questions_rect.set(Rect::new(33, 13, 67, 8));
        app.hex_rect.set(Rect::new(33, 21, 67, 12));
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

    #[test]
    fn mouse_click_unfold_above_keeps_selection() {
        use ratatui::layout::Rect;
        let mut app = two_group_app();
        select_instance(&mut app, "Test");
        // Collapse the host above the selection, then click its header to
        // unfold: the inserted rows must not steal the cursor.
        app.collapsed_hosts.insert("shell.local".to_string());
        app.left_rect.set(Rect::new(0, 3, 33, 30));
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        let header = app
            .display_items()
            .iter()
            .position(|it| matches!(it, DisplayItem::Host { label } if label == "shell.local"))
            .expect("shell header");
        app.click_service_list(3 + 1 + header as u16);
        assert!(!app.is_host_collapsed("shell.local"));
        assert!(
            matches!(app.display_items().get(app.selected_display),
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
        assert!(matches!(app.display_items().get(app.selected_display),
                Some(DisplayItem::Instance { index }) if app.services[*index].instance == "Test"),);
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
            let sel_idx = match app.display_items().get(app.selected_display) {
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
        assert_eq!(app.focus, Focus::Answers);
        assert!(app.detail_selected < raw_count);
        app.hex_offset.set(9);
        app.handle_key(&plain(KeyCode::Tab));
        assert_eq!(app.focus, Focus::Questions);
        assert_eq!(app.detail_selected, raw_count);
        assert_eq!(app.hex_offset.get(), 0);
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
        app.focus = Focus::Services;
        let before = app.selected_display;
        app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
        assert_ne!(app.selected_display, before);
        app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
        assert_eq!(app.selected_display, before);
        // Answers: one notch moves the record cursor one row.
        service_with_txt(&mut app, "a=1; b=2");
        app.focus = Focus::Answers;
        let cursor = app.detail_selected;
        assert!(cursor > 0);
        app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
        assert_eq!(app.detail_selected, cursor - 1);
        app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
        assert_eq!(app.detail_selected, cursor);
        // Hex: one notch scrolls the dump one line.
        app.focus = Focus::Hex;
        app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
        assert_eq!(app.hex_offset.get(), 1);
        app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
        assert_eq!(app.hex_offset.get(), 0);
        // Anomalies: one notch scrolls the findings one line.
        app.focus = Focus::Anomalies;
        app.anomalies_offset.set(0);
        app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
        assert_eq!(app.anomalies_offset.get(), 1);
        app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
        assert_eq!(app.anomalies_offset.get(), 0);
        // Metrics overlay owns the wheel while open.
        app.show_metrics = true;
        app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
        assert_eq!(app.metrics_scroll.get(), 1);
        assert_eq!(app.detail_selected, cursor);
        // Horizontal wheel is ignored everywhere.
        app.show_metrics = false;
        app.handle_mouse(&wheel(MouseEventKind::ScrollLeft));
        app.handle_mouse(&wheel(MouseEventKind::ScrollRight));
        assert_eq!(app.hex_offset.get(), 0);
        assert_eq!(app.detail_selected, cursor);
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
        let sel_idx = match app.display_items().get(app.selected_display) {
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
        assert_eq!(app.focus, Focus::Questions);
        assert_eq!(app.detail_selected, raws);
        app.handle_mouse(&wheel(MouseEventKind::ScrollDown));
        assert_eq!(app.detail_selected, raws + 1);
        app.handle_mouse(&wheel(MouseEventKind::ScrollUp));
        assert_eq!(app.detail_selected, raws);
    }

    #[test]
    fn mouse_click_selects_service_and_focuses() {
        use ratatui::layout::Rect;
        let mut app = two_group_app();
        app.focus = Focus::Answers;
        // Left pane shows: enum header, enum row, then host groups.
        let items = app.display_items();
        let first_instance = items
            .iter()
            .position(|it| matches!(it, DisplayItem::Instance { .. }))
            .expect("instance row");
        app.list_offset.set(0);
        app.left_rect.set(Rect::new(0, 3, 33, 30));
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        app.answers_rect.set(Rect::new(33, 3, 67, 10));
        app.questions_rect.set(Rect::new(33, 13, 67, 10));
        app.hex_rect.set(Rect::new(33, 23, 67, 10));
        let row = 3 + 1 + first_instance as u16;
        app.click_service_list(row);
        assert_eq!(app.focus, Focus::Services);
        assert_eq!(app.selected_display, first_instance);
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
        app.list_offset.set(0);
        app.left_rect.set(Rect::new(0, 3, 33, 30));
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        app.answers_rect.set(Rect::default());
        app.questions_rect.set(Rect::default());
        app.hex_rect.set(Rect::default());
        let row = 3 + 1 + header as u16;
        app.click_service_list(row);
        assert!(!app.collapsed_hosts.is_empty());
    }

    #[test]
    fn mouse_click_answers_selects_record() {
        use ratatui::layout::Rect;
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "a=1; b=2");
        app.focus = Focus::Services;
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        app.answers_rect.set(Rect::new(33, 3, 67, 20));
        app.questions_rect.set(Rect::new(33, 24, 67, 8));
        app.hex_rect.set(Rect::default());
        app.detail_offset.set(0);
        // Table rows: 1 info row, then PTR/SRV/TXT in type order.
        let info = 1;
        let raws = app
            .display_detail()
            .expect("detail")
            .ordered_answers()
            .len();
        assert!(raws >= 2);
        let row = 3 + 2 + (info + 1) as u16;
        app.click_answers(row);
        assert_eq!(app.focus, Focus::Answers);
        assert_eq!(app.detail_selected, 1);
    }

    #[test]
    fn mouse_click_answers_child_selects_parent() {
        use ratatui::layout::Rect;
        let mut app = App::new().unwrap();
        service_with_txt(&mut app, "a=1; b=2");
        assert!(app.toggle_txt_expanded());
        app.right_rect.set(Rect::new(33, 3, 67, 30));
        app.answers_rect.set(Rect::new(33, 3, 67, 20));
        app.questions_rect.set(Rect::new(33, 24, 67, 8));
        app.hex_rect.set(Rect::default());
        app.detail_offset.set(0);
        // Info(1) + PTR(1) + SRV(1) + TXT parent(1), then 2 child rows.
        // Clicking the first child must land on the TXT parent (index 2).
        let row = 3 + 2 + 4u16;
        app.click_answers(row);
        assert_eq!(app.detail_selected, 2);
    }
}
