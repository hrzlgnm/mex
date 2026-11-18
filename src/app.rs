// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

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
use crate::devices::AddressBook;
use crate::dump;
use crate::ui;

/// Pane with keyboard focus: Tab cycles the service list, the two
/// record tables, and the hex dump. Arrows and j/k navigate inside the
/// focused pane; the hex pane has no cursor, so its keys scroll.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Focus {
    #[default]
    Services,
    Answers,
    Questions,
    Hex,
}

/// Which pane divider is being dragged (or hovered) with the mouse.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum DragMode {
    #[default]
    None,
    Vertical,
    /// Answers | Questions.
    HorizUpper,
    /// Questions | Hex.
    HorizLower,
}

#[derive(Clone, PartialEq, Eq)]
pub enum DisplayItem {
    Host {
        label: String,
    },
    Instance {
        index: usize,
    },
    Enum {
        index: usize,
    },
    /// The selectable row under the `(unattributed)` group: findings
    /// whose evidence names no known service, host or enumeration row.
    Unattributed,
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

/// Liveness of a record row for finding purposes. Goodbye rows (TTL 0)
/// and rows past their TTL carry no findings: only live rows get a
/// marker or finding child rows.
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

/// Identity of the cursor row, so the selection survives resorting of the
/// table (TTL countdowns and re-announcements constantly reshuffle rows).
/// Matches the dedup identities used at ingest.
/// Identity of one expandable TXT row: per link, like every row (#264).
type TxtKey = (String, String, std::net::SocketAddr, u32);

#[derive(Clone, PartialEq, Eq)]
enum DetailCursorKey {
    Record {
        name: String,
        rtype: u16,
        rdata: String,
        source: std::net::SocketAddr,
        ifindex: u32,
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
    /// Rows evicted by the safety cap (`QUESTION_CAP`) inside the
    /// question window; surfaced in dumps so a capped list is never
    /// mistaken for a complete one. Age-outs don't count.
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

/// DNS-SD service type enumeration name (RFC 6763 §9), without the
/// trailing root dot.
pub(crate) const ENUM_SERVICE: &str = "_services._dns-sd._udp.local";
/// Group header for the selectable enumeration row in the Hosts pane.
pub const ENUM_HOST: &str = "(enumeration)";
/// Group header for the `(unattributed)` findings row in the Hosts pane,
/// present only while such findings exist.
pub const UNATTRIBUTED_HOST: &str = "(unattributed)";

/// Whether a response carries a non-zero RCODE, which RFC 6762 §18.11
/// says MUST be silently ignored on receipt.
fn has_nonzero_rcode(ev: &browse::Event) -> bool {
    ev.rcode.is_some_and(|rcode| rcode != 0)
}

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
    if !browse::is_sub_label(sub_keyword) {
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
/// path (our own looped-back copies are dropped by the listener, so our
/// transmissions never arrive as events). Port 0 can never be a real mDNS
/// querier.
pub const SELF_SOURCE: std::net::SocketAddr =
    std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 0);

/// How `SELF_SOURCE` is spelled wherever a querier is shown (Questions
/// pane, state dump), instead of the meaningless `0.0.0.0:0`.
pub const SELF_SOURCE_LABEL: &str = "self";

/// Whether a record `elapsed` seconds old has reached its 80%-TTL refresh
/// window (RFC 6762 §5.2). Widened to u64: TTLs are unbounded u32 from the
/// wire, so `ttl * 4` would overflow for TTLs of 2^30 s or more.
fn in_refresh_window(elapsed: u32, ttl: u32) -> bool {
    u64::from(elapsed) * 5 >= u64::from(ttl) * 4
}

/// Identity of one cached row for refresh bookkeeping: refresh key, then
/// source, rdata and receive time. A re-announcement replaces the row
/// with a new `received_at`, so it gets a fresh identity.
type RefreshRow = (String, u16, std::net::SocketAddr, String, Instant);

/// A row inside its refresh window this pass: identity, TTL, and
/// whether its own next attempt is due.
type PendingRow = (RefreshRow, u32, bool);

/// Refresh progress of one cached row: queries so far (sent or
/// suppressed) and when the next one is due.
#[derive(Clone, Copy, Debug)]
struct RowRefresh {
    next_due: Instant,
    attempts: u8,
}

/// Refresh queries per row before it is left to expire (RFC 6762 §5.2).
const REFRESH_ATTEMPTS: u8 = 4;

fn refresh_row(rec: &browse::RawRecord) -> RefreshRow {
    (
        rec.name.trim_end_matches('.').to_string(),
        rec.rtype,
        rec.source,
        rec.rdata.clone(),
        rec.received_at,
    )
}

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

/// How long after a question a unicast-style response is still
/// attributed to it. RFC 6762 §6 delays responses by at most ~500ms
/// (aggregation), so 1s covers every compliant responder without
/// reaching back to an unrelated earlier question.
const TRIGGER_WINDOW: Duration = Duration::from_secs(1);
/// Packet arrival times older than this are dropped from the rate window.
const METRICS_WINDOW: Duration = Duration::from_secs(300);

/// Bound on out-of-scope sightings, so a peer flooding distinct
/// unsupported records cannot grow state without limit. The oldest is
/// evicted first and counted in `MetricsCounters::sightings_dropped`.
const SIGHTINGS_CAP: usize = 256;

/// How long a Questions-pane row lives after its querier last asked
/// (#238). Equal to the long mDNS TTL (4500 s): our own steady demand
/// (continuous browsing capped hourly, refreshes at 80–95% of a 4500 s
/// TTL) and any well-behaved steady querier re-ask inside it, so their
/// rows don't flicker out between asks. Revisit if either changes.
pub(crate) const QUESTION_WINDOW: Duration = Duration::from_secs(4500);

/// Safety cap per Questions list inside the window: bounds memory
/// against floods of distinct queriers. Only these evictions count as
/// drops (`questions_dropped`); ageing out is expected, not truncation.
const QUESTION_CAP: usize = 100;

/// How long an out-of-scope question sighting lives after its last ask.
/// Questions carry no TTL; this matches the interest grace window.
const QUESTION_SIGHTING_LIFETIME: Duration = INTEREST_GRACE;

/// Where an out-of-scope sighting came from: it decides lifetime,
/// goodbye handling and which analyzer checks run.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SightingKind {
    /// A record in a response (answer, authority or additional).
    Response,
    /// A known answer carried in a query (RFC 6762 §7.1): a belief, so
    /// never a goodbye; its finding names the Known-Answer section.
    KnownAnswer,
    /// An observed question.
    Question,
}

/// One out-of-scope record or question. Records carry only
/// `rdlength=<n>` as rdata and no wire bytes (see `browse::record_row`).
/// No owner is stored: attribution runs at analysis time
/// (`App::sighting_owners`), so a host that appears later still claims
/// its earlier sightings.
#[derive(Debug, Clone)]
struct Sighting {
    kind: SightingKind,
    rec: browse::RawRecord,
}

impl Sighting {
    fn is_live(&self, now: Instant) -> bool {
        let age = now.saturating_duration_since(self.rec.received_at);
        match self.kind {
            SightingKind::Question => age < QUESTION_SIGHTING_LIFETIME,
            SightingKind::Response | SightingKind::KnownAnswer => {
                self.rec.ttl > 0 && age.as_secs() <= u64::from(self.rec.ttl)
            }
        }
    }

    /// The record a goodbye withdraws: same kind, owner, type, source
    /// and ingress link, in any response context. The link counts
    /// because an IPv4 source carries no scope: the same address on two
    /// links is two responders, each with its own finding.
    fn same_record(&self, kind: SightingKind, rec: &browse::RawRecord) -> bool {
        self.kind == kind
            && self.rec.rtype == rec.rtype
            && self.rec.source == rec.source
            && self.rec.ifindex == rec.ifindex
            && self.rec.name.eq_ignore_ascii_case(&rec.name)
    }

    /// Dedup identity without rdata: a newer sighting of the same record
    /// in the same response context (section, multicast vs unicast)
    /// replaces the older one (e.g. SOA serial bumps). Contexts stay
    /// apart because they carry different verdicts (e.g. SOA in
    /// Authority vs Additional).
    fn same_identity(&self, kind: SightingKind, rec: &browse::RawRecord) -> bool {
        self.same_record(kind, rec)
            && self.rec.section == rec.section
            && self.rec.dst_is_multicast == rec.dst_is_multicast
    }
}

/// How a responder said an address type is absent for a service.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DenialForm {
    /// RFC 6762 §6.1: a hostname-owned NSEC, arriving in the same packet
    /// as the service's SRV for that host, whose bitmap lists the types
    /// that exist; absent address types are denied.
    Rfc,
    /// Older python-zeroconf: an instance-owned NSEC whose bitmap lists
    /// only the *missing* address types (inverted bitmap).
    Legacy,
}

impl DenialForm {
    pub fn as_str(self) -> &'static str {
        match self {
            DenialForm::Rfc => "rfc",
            DenialForm::Legacy => "legacy",
        }
    }
}

/// A service's own responder said it has no address of `rtype` (A or
/// AAAA): rows of that type stay off this service while it is live.
#[derive(Debug, Clone)]
struct AddressDenial {
    /// Lowercased `instance.service_type` (`service_key`).
    service: String,
    rtype: u16,
    /// The hostname it applies to (RFC form); `None` for every host of
    /// the service (legacy, instance-owned form).
    host: Option<String>,
    form: DenialForm,
    source: std::net::SocketAddr,
    ttl: u32,
    received_at: Instant,
}

impl AddressDenial {
    fn is_live(&self) -> bool {
        self.ttl > 0 && self.received_at.elapsed().as_secs() <= u64::from(self.ttl)
    }

    /// Whether this denial is about an address of `rtype` owned by `host`.
    fn applies_to(&self, rtype: u16, host: &str) -> bool {
        self.rtype == rtype && self.host.as_deref().is_none_or(|h| h == host)
    }

    fn covers(&self, service: &str, rtype: u16, host: &str) -> bool {
        self.service == service && self.applies_to(rtype, host) && self.is_live()
    }
}

/// Lowercased `instance.service_type`, the identity address denials use.
fn service_key(instance: &str, service_type: &str) -> String {
    format!("{instance}.{service_type}").to_lowercase()
}

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
    /// Out-of-scope sightings evicted by `SIGHTINGS_CAP`.
    pub sightings_dropped: u64,
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
    /// Answers and Questions (the hex pane takes the remainder). The
    /// shared pane borders are mouse-draggable.
    pub answers_pct: u16,
    pub questions_pct: u16,
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
    /// Bumped by anything that can change the list or detail selection
    /// (ingest, eviction, input); `evict_expired` re-clamps the cursors
    /// only when it moved past `clamped_gen`, not on every idle tick.
    state_gen: u64,
    clamped_gen: Option<u64>,
    /// Cached usable/skipped link snapshot, refreshed on the 10s tick.
    pub link_stats: browse::LinkStats,
    /// Refused-packet accounting from the listener thread (RFC 6762 §11).
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
    /// Per-interest summary of `refresh_rows` for the UI and dumps:
    /// (earliest next refresh due, highest unanswered count) over the
    /// rows of a (name, type) still being refreshed. Rebuilt by every
    /// `requery_expiring` pass; answers clear it early via push_record.
    requeries: HashMap<(String, u16), (Instant, u8)>,
    /// Refresh schedule per cached row (RFC 6762 §5.2): a querier SHOULD
    /// re-ask at 80% of the row's TTL, then 85/90/95% if no answer
    /// arrives, with ~2% random variation; after four misses the row
    /// expires at 100% (no hourly refresh — hourly is only the cap for
    /// *unanswered* continuous browsing). Rows sharing a question are
    /// tracked separately so each gets its own four attempts on its own
    /// TTL. A re-announcement replaces the row and starts it afresh.
    /// Pruned to live rows in `requery_expiring`.
    refresh_rows: HashMap<RefreshRow, RowRefresh>,
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
    /// Queries are on hold because no family can transmit (no usable
    /// link on either, or `-i` naming only down links): nothing is
    /// counted as sent and no schedule advances until one resumes.
    transmit_held: bool,
    last_ip_refresh: Instant,
    collapsed_hosts: HashSet<String>,
    /// Expanded TXT records in the Answers table, keyed by
    /// (name, rdata, source). Absent = collapsed (the default), so
    /// multi-pair TXT rows render as a single `▸ TXT` line until
    /// `Enter` expands them into `▾ TXT` plus child rows.
    expanded_txt: HashSet<TxtKey>,
    local_ips: HashSet<std::net::IpAddr>,
    /// Recently overheard QM questions from other queriers (RFC 6762 §7.3):
    /// key (lowercased name, type) -> (seen_at, remote KA targets lowercased
    /// and dot-trimmed, ingress iface). Consumed to suppress our own
    /// duplicate once; pruned after OVERHEARD_WINDOW. Own loopback and QU
    /// questions are never stored.
    overheard: HashMap<(String, u16), (Instant, HashSet<String>, String)>,
    detail_svc_key: Option<(String, String)>,
    detail_enum_key: Option<String>,
    /// Whether the detail cursor last synced onto `(unattributed)`.
    detail_unattributed: bool,
    detail_anchor: Option<DetailCursorKey>,
    sticky_key: Option<(String, String)>,
    sticky_enum_key: Option<String>,
    /// `(unattributed)` was the last selected target (sticky like the
    /// service and enumeration keys).
    sticky_unattributed: bool,
    /// Row -> record index of the Answers table as last drawn (`None` per
    /// info, block or unowned row), so a click hits what was on screen
    /// even if findings changed since. `None` before the first draw.
    pub answers_rows: RefCell<Option<Vec<Option<usize>>>>,
    /// Row -> question index of the Questions table as last drawn.
    pub questions_rows: RefCell<Option<Vec<Option<usize>>>>,
    /// Selectable enumeration row. Always present so our own enumeration
    /// demand has a home; answers and questions file here instead of
    /// being skipped as noise.
    pub enum_entries: Vec<EnumEntry>,
    pending_instances: Vec<PendingService>,
    pending_addrs: HashMap<String, Vec<browse::RawRecord>>,
    next_pending_addr_prune: Instant,
    pub raw_events: Vec<browse::Event>,
    /// Out-of-scope records and questions (`anomalies::is_mdns_answer_type`
    /// / `is_mdns_question_type` false), kept only as evidence for
    /// findings: never Answers or Questions rows, never query drivers.
    /// Oldest first, capped at `SIGHTINGS_CAP`.
    sightings: Vec<Sighting>,
    /// Address types a service's own responder denies via NSEC (#245):
    /// rows of that type are never filed on that service.
    address_denials: Vec<AddressDenial>,
    /// Address records withheld from every service of their host by a
    /// denial, by lowercased host: the Hosts header still lists them.
    withheld_addrs: HashMap<String, Vec<browse::RawRecord>>,
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
    /// (name, type, querier, received_at, query packet bytes). Aged out
    /// after `QUESTION_WINDOW`, bounded by `QUESTION_CAP`.
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
            // One row per link too (#264): the same record from one source
            // on two links is two observations.
            if seen.insert((&rec.name, rec.rtype, &rec.rdata, rec.source, rec.ifindex)) {
                out.push(rec);
            }
        }
        out.sort_by(|a, b| {
            (&a.rtype_str, a.source, &a.name, &a.rdata, a.ifindex).cmp(&(
                &b.rtype_str,
                b.source,
                &b.name,
                &b.rdata,
                b.ifindex,
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
            (&a.1, std::cmp::Reverse(a.3), a.2, &a.0).cmp(&(
                &b.1,
                std::cmp::Reverse(b.3),
                b.2,
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
                rec.ifindex,
            )) {
                out.push(rec);
            }
        }
        out.sort_by(|a, b| {
            (&a.rtype_str, a.source, &a.name, &a.rdata, a.ifindex).cmp(&(
                &b.rtype_str,
                b.source,
                &b.name,
                &b.rdata,
                b.ifindex,
            ))
        });
        out
    }

    pub fn ordered_questions(
        &self,
    ) -> Vec<&(String, String, std::net::SocketAddr, Instant, Vec<u8>)> {
        let mut out: Vec<_> = self.questions.iter().collect();
        out.sort_by(|a, b| {
            (&a.1, std::cmp::Reverse(a.3), a.2, &a.0).cmp(&(
                &b.1,
                std::cmp::Reverse(b.3),
                b.2,
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
    /// Findings with no owner: no records or questions of its own.
    Unattributed,
}

impl<'a> DetailTarget<'a> {
    pub fn ordered_answers(&self) -> Vec<&'a browse::RawRecord> {
        match self {
            DetailTarget::Service(s) => s.ordered_answers(),
            DetailTarget::Enum(e) => e.ordered_answers(),
            DetailTarget::Unattributed => Vec::new(),
        }
    }

    pub fn ordered_questions(
        &self,
    ) -> Vec<&'a (String, String, std::net::SocketAddr, Instant, Vec<u8>)> {
        match self {
            DetailTarget::Service(s) => s.ordered_questions(),
            DetailTarget::Enum(e) => e.ordered_questions(),
            DetailTarget::Unattributed => Vec::new(),
        }
    }

    pub fn questions_len(&self) -> usize {
        match self {
            DetailTarget::Service(s) => s.questions.len(),
            DetailTarget::Enum(e) => e.questions.len(),
            DetailTarget::Unattributed => 0,
        }
    }

    pub fn all_answers(&self) -> &'a [browse::RawRecord] {
        match self {
            DetailTarget::Service(s) => &s.answers,
            DetailTarget::Enum(e) => &e.answers,
            DetailTarget::Unattributed => &[],
        }
    }

    pub fn last_event(&self) -> Option<&'a browse::Event> {
        match self {
            DetailTarget::Service(s) => s.last_event.as_ref(),
            DetailTarget::Enum(e) => e.last_event.as_ref(),
            DetailTarget::Unattributed => None,
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
            DetailTarget::Unattributed => UNATTRIBUTED_HOST.to_string(),
        }
    }
}

/// One line of the Answers table: the single layout both rendering and
/// mouse mapping use, so they can't drift (#248).
#[derive(Debug, Clone)]
pub enum AnswerLine {
    /// Derived summary row (`srvc`, `subt`, `enum`).
    Info { label: &'static str, text: String },
    /// Cursor-skipped header of a finding block: `service`, `host <name>`,
    /// or, in the unattributed view, the record or question name.
    Block(String),
    /// A finding shown next to its owner; `record` is the owning record's
    /// index in `ordered_answers`, `None` when it sits under a block.
    Finding {
        // Boxed: findings carry responder lists (#247), far larger than
        // the other line kinds.
        anomaly: Box<anomalies::Anomaly>,
        record: Option<usize>,
    },
    /// A record row: index into `ordered_answers` (the detail cursor's
    /// index space).
    Record(usize),
    /// One `key=value` child of a multi-pair TXT record.
    TxtPair {
        record: usize,
        pair: String,
        last: bool,
    },
}

impl AnswerLine {
    /// The record a click on this line selects, if any.
    pub fn owning_record(&self) -> Option<usize> {
        match self {
            AnswerLine::Record(i) | AnswerLine::TxtPair { record: i, .. } => Some(*i),
            AnswerLine::Finding { record, .. } => *record,
            AnswerLine::Info { .. } | AnswerLine::Block(_) => None,
        }
    }
}

/// Whether a finding is about this exact record row: same owner name,
/// type and rdata (spanning `ttl-unstable` findings carry no rdata and
/// match every row of the name and type).
fn finding_matches_record(a: &anomalies::Anomaly, rec: &browse::RawRecord) -> bool {
    // A sourced finding is about one responder's copy: another source's
    // identical row must not inherit it. Findings carry either the bare
    // socket address or the interface-qualified label.
    let same_source = a
        .source
        .as_deref()
        .is_none_or(|src| src == rec.source.to_string() || src == rec.source_label());
    same_source
        && a.rtype == Some(rec.rtype)
        && a.record_name.as_ref().is_some_and(|n| {
            n.trim_end_matches('.')
                .eq_ignore_ascii_case(rec.name.trim_end_matches('.'))
        })
        && match a.rdata.as_ref() {
            Some(rdata) => *rdata == rec.rdata,
            None => a.kind == anomalies::AnomalyKind::TtlUnstable,
        }
}

/// Whether a question finding is about this Questions row (name, type,
/// querier).
fn finding_matches_question(
    a: &anomalies::Anomaly,
    name: &str,
    rtype_str: &str,
    source: &std::net::SocketAddr,
) -> bool {
    a.kind.is_question()
        && a.rtype.is_some()
        && browse::rtype_from_str(rtype_str) == a.rtype
        && a.record_name.as_ref().is_some_and(|n| {
            n.trim_end_matches('.')
                .eq_ignore_ascii_case(name.trim_end_matches('.'))
        })
        && a.source.as_deref() == Some(source.to_string().as_str())
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
        // Tests must not depend on the host's interfaces: pin both
        // families to "can transmit"; hold tests pin their own state.
        #[cfg(test)]
        query_tx.transmit().pin(true, true);
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
            refresh_rows: HashMap::new(),
            query_history: HashMap::new(),
            enum_known: HashMap::new(),
            startup_qu_sent: false,
            transmit_held: false,
            last_ip_refresh: Instant::now(),
            collapsed_hosts: HashSet::new(),
            expanded_txt: HashSet::new(),
            local_ips: browse::local_ips(),
            overheard: HashMap::new(),
            detail_selected: 0,
            detail_offset: Cell::new(0),
            detail_free_scroll: false,
            questions_offset: Cell::new(0),
            hex_offset: Cell::new(0),
            hex_viewport: Cell::new(0),
            hex_selected_field: Cell::new(None),
            left_pct: 33,
            // The Answers pane holds finding child rows (#248): it gets
            // the larger share.
            answers_pct: 50,
            questions_pct: 25,
            drag: DragMode::None,
            hover: Cell::new(DragMode::None),
            body_rect: Cell::new(Rect::default()),
            left_rect: Cell::new(Rect::default()),
            right_rect: Cell::new(Rect::default()),
            answers_rect: Cell::new(Rect::default()),
            questions_rect: Cell::new(Rect::default()),
            hex_rect: Cell::new(Rect::default()),
            hex_field_hits: RefCell::new(Vec::new()),
            detail_svc_key: None,
            detail_enum_key: None,
            detail_unattributed: false,
            answers_rows: RefCell::new(None),
            questions_rows: RefCell::new(None),
            detail_anchor: None,
            sticky_key: None,
            sticky_enum_key: None,
            sticky_unattributed: false,
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
            sightings: Vec::new(),
            address_denials: Vec::new(),
            withheld_addrs: HashMap::new(),
            status_msg: None,
            show_metrics: false,
            metrics_scroll: Cell::new(0),
            metrics_viewport: Cell::new(0),
            metrics_hscroll: Cell::new(0),
            metrics: MetricsCounters::default(),
            state_gen: 0,
            clamped_gen: None,
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
        // Redraw only when something changed: input, new packets, a log
        // popup, or the wall-clock second ticking over (TTL countdowns,
        // ages, uptime, popup expiry). The 80ms tick itself stays for
        // query scheduling; idle ticks skip the costly frame.
        let mut dirty = true;
        let mut drawn_sec = None;
        while self.running {
            let packets_before = self.packet_count;
            self.drain_events();
            self.send_queries();
            self.evict_expired();
            dirty |= self.packet_count != packets_before;

            // Surface retained log write failures (terminal-safe: the
            // popup, not stderr, so the TUI is not corrupted).
            if let Some(msg) = crate::take_log_error() {
                self.status_msg = Some((msg, Instant::now()));
                dirty = true;
            }

            let sec = self.start_time.elapsed().as_secs();
            if dirty || drawn_sec != Some(sec) {
                terminal.draw(|f| ui::draw(f, self))?;
                dirty = false;
                drawn_sec = Some(sec);
            }

            if event::poll(Duration::from_millis(80))? {
                // Any input may change what is shown (keys, mouse hover,
                // resize): draw on the next pass.
                dirty = true;
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
                        Event::Resize(_, _) => self.touch(),
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
            .filter(|ev| !has_nonzero_rcode(ev))
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
        self.update_refreshes(true);
    }

    /// Track live rows' refresh state and rebuild the per-question
    /// summaries; with `send`, also fire due refresh queries. Without
    /// it (transmission on hold) nothing is sent and no attempt is used:
    /// expired or replaced rows just drop out.
    fn update_refreshes(&mut self, send: bool) {
        let now = Instant::now();
        // Live rows inside their 80% window with attempts left, grouped by
        // question, each flagged whether its own next attempt is due.
        // Several rows (sources, rdata) share one question; each keeps
        // its own TTL and count, so one row can neither set another's
        // pace nor use up its attempts. Expired rows (elapsed > TTL) are
        // not refreshed: RFC 6762 §5.2 deletes the record at 100% after
        // four unanswered queries.
        let mut pending: HashMap<(String, u16), Vec<PendingRow>> = HashMap::new();
        let mut live_rows: HashSet<RefreshRow> = HashSet::new();
        let tracked = &self.refresh_rows;
        let mut scan = |rec: &browse::RawRecord| {
            if rec.ttl == 0 {
                return;
            }
            match rec.rtype {
                12 | 33 | 16 | 1 | 28 => {}
                _ => return,
            }
            let elapsed = rec.received_at.elapsed().as_secs() as u32;
            if elapsed > rec.ttl {
                return;
            }
            let row = refresh_row(rec);
            // One A/AAAA row is filed under every service of its host;
            // count it once, or a single query would use up several of
            // its attempts.
            if !live_rows.insert(row.clone()) || !in_refresh_window(elapsed, rec.ttl) {
                return;
            }
            let state = tracked.get(&row);
            if state.is_some_and(|s| s.attempts >= REFRESH_ATTEMPTS) {
                return;
            }
            let due = state.is_none_or(|s| now >= s.next_due);
            pending
                .entry((row.0.clone(), row.1))
                .or_default()
                .push((row, rec.ttl, due));
        };
        for svc in &self.services {
            svc.answers.iter().for_each(&mut scan);
        }
        for entry in &self.enum_entries {
            entry.answers.iter().for_each(&mut scan);
        }
        // No maintenance without a live record (RFC 6762 §5.2 deletes at
        // 100%); a replaced row is gone with its old identity.
        self.refresh_rows.retain(|r, _| live_rows.contains(r));
        let fired: Vec<_> = if send {
            pending
                .iter()
                .filter(|(_, rows)| rows.iter().any(|(_, _, due)| *due))
                .map(|(key, _)| key.clone())
                .collect()
        } else {
            Vec::new()
        };
        if !fired.is_empty() {
            log::debug!(
                "mex: cache refresh triggered for {} interest(s)",
                fired.len()
            );
        }
        for key in fired {
            if !self.send_refresh(&key, now) {
                continue;
            }
            // 0-2% random variation so queriers do not stay in lockstep
            // (RFC 6762 §5.2: 80-82%, 85-87%, 90-92%, 95-97%). No 1s floor
            // here: the >=1s rule applies to the continuous stream, while
            // refresh spacing is 5% of the TTL (floors would push small
            // TTLs past 100%). Only rows whose own attempt was due count
            // this query; the others keep their pace.
            let jitter_pct = rand_u32() % 201;
            for (row, ttl, due) in &pending[&key] {
                if !due {
                    continue;
                }
                let state = self.refresh_rows.entry(row.clone()).or_insert(RowRefresh {
                    next_due: now,
                    attempts: 0,
                });
                state.attempts += 1;
                state.next_due = now + refresh_step(*ttl, jitter_pct);
            }
        }
        // Per-question summary for the UI: rows that used up their four
        // attempts drop out and are left to expire at 100%.
        self.requeries.clear();
        for (key, rows) in pending {
            let summary = rows
                .iter()
                .filter_map(|(row, _, _)| self.refresh_rows.get(row))
                .filter(|s| s.attempts < REFRESH_ATTEMPTS)
                .fold(None, |acc: Option<(Instant, u8)>, s| {
                    Some(match acc {
                        Some((due, n)) => (due.min(s.next_due), n.max(s.attempts)),
                        None => (s.next_due, s.attempts),
                    })
                });
            if let Some(summary) = summary {
                self.requeries.insert(key, summary);
            }
        }
    }

    /// Transmit one refresh query for `key`, or count it as sent when an
    /// overheard query already asked it (RFC 6762 §7.3). Returns whether
    /// the attempt counts (false only for an unsupported record type).
    fn send_refresh(&mut self, key: &(String, u16), now: Instant) -> bool {
        let Some(rt) = browse::record_type_from_u16(key.1) else {
            return false;
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
        if self.suppressed_by_overheard(key, &ka) {
            log::debug!("mex: suppressed refresh query for {} (overheard)", key.0);
            self.metrics.suppressed_refresh += 1;
            self.metrics.suppressed_times.push_back(now);
            self.note_query(&key.0, key.1, QueryOrigin::Suppressed, now);
        } else {
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
        }
        self.route_own_question(&key.0, key.1, false);
        // A refresh query also elicits new answers, so postpone the
        // exponential stream for the same question: otherwise the two
        // timers can fire on the same tick and emit back-to-back
        // duplicates (RFC 6762 §5.2 spacing).
        self.postpone_continuous_for_refresh(key, now);
        true
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
            // Rows that used up their four attempts only wait to expire.
            if self
                .refresh_rows
                .get(&refresh_row(rec))
                .is_some_and(|s| s.attempts >= REFRESH_ATTEMPTS)
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
                // A denied address type is no interest of this service:
                // only other services (or other demand) keep asking.
                let host = svc.hostname.trim_end_matches('.').to_string();
                let key = service_key(&svc.instance, &svc.service_type);
                let host_key = host.to_lowercase();
                for rtype in [1, 28] {
                    if !self
                        .address_denials
                        .iter()
                        .any(|d| d.covers(&key, rtype, &host_key))
                    {
                        want(host.clone(), rtype);
                    }
                }
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
                    // A unique answer cached before the interest appeared
                    // (e.g. A/AAAA shipped as additionals with the SRV)
                    // means no other answers are forthcoming: start
                    // dampened, as the flush-bit path would, and let the
                    // 80%-TTL refresh maintain it. The interest is still
                    // demand: file its self row now so the Questions pane
                    // shows it pending (LAST "—", DUE the refresh) instead
                    // of hiding it until the first refresh fires.
                    let (next_due, interval) = if self.has_fresh_unique_answer(&key) {
                        self.route_own_question(&qname, key.1, false);
                        (now + MAX_CONTINUOUS_INTERVAL, MAX_CONTINUOUS_INTERVAL)
                    } else {
                        (now + rand_range(20, 120), Duration::from_secs(1))
                    };
                    self.continuous.insert(
                        key.clone(),
                        ContinuousQuery {
                            next_due,
                            interval,
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

            // While no family can transmit, queries would be queued and
            // dropped by the listener: hold both schedules instead, so
            // nothing is counted as sent, discovery doesn't back off, and
            // refresh attempts aren't used up (records still expire at
            // 100% TTL). When a family resumes, restart discovery with the
            // RFC 6762 §5.2 startup schedule, as for an interface coming
            // up: clearing the streams re-creates them through the normal
            // first-query path (20–120 ms jitter, dampening, startup QU).
            let can_transmit = self.query_tx.transmit().any();
            if !can_transmit {
                if !self.transmit_held {
                    log::info!("mex: no family can transmit; queries on hold");
                }
                self.transmit_held = true;
                // Keep the refresh bookkeeping honest without sending:
                // expired or replaced rows drop out, live rows keep their
                // attempts and next due time.
                self.update_refreshes(false);
            } else {
                if self.transmit_held {
                    log::info!("mex: transmission resumed; restarting discovery");
                    self.continuous.clear();
                    self.transmit_held = false;
                    // Links just came back: take a fresh interface
                    // snapshot first, so resumed queries record the
                    // interfaces they really went out on.
                    self.refresh_link_snapshot();
                }
                self.requery_expiring();
                self.poll_continuous();
            }
        }

        // Refresh in case interfaces/addresses changed (cheap: ~1 fork/min).
        // Independent of query backoff.
        if self.last_ip_refresh.elapsed() >= LOCAL_IPS_REFRESH {
            self.refresh_link_snapshot();
        }
    }

    /// Re-read local addresses and per-link interface stats (the
    /// snapshot `note_query` records as a query's interfaces).
    fn refresh_link_snapshot(&mut self) {
        self.last_ip_refresh = Instant::now();
        self.local_ips = browse::local_ips();
        self.link_stats = browse::link_stats(self.interfaces.as_ref());
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
        // Findings with no owner, after the host groups; only while any
        // exist, so a clean network shows no extra entry.
        if self.has_unattributed() {
            items.push(DisplayItem::Host {
                label: UNATTRIBUTED_HOST.to_string(),
            });
            if !self.collapsed_hosts.contains(UNATTRIBUTED_HOST) {
                items.push(DisplayItem::Unattributed);
            }
        }
        items
    }

    /// Every A/AAAA record held for each hostname a live service points
    /// at (live SRV targets): filed service rows (deduped across the
    /// services sharing the host), pending addresses and withheld
    /// (NSEC-denied) addresses. Input of `conflicting-answers` (#247).
    fn host_address_views(&self) -> Vec<anomalies::HostAddressView<'_>> {
        let mut hosts: Vec<String> = Vec::new();
        for svc in &self.services {
            for host in Self::service_hosts(svc) {
                if !hosts.contains(&host) {
                    hosts.push(host);
                }
            }
        }
        hosts
            .into_iter()
            .map(|host| {
                let mut seen = HashSet::new();
                let records = self
                    .services
                    .iter()
                    .flat_map(|s| s.answers.iter())
                    .filter(|r| matches!(r.rtype, 1 | 28) && anomalies::host_id(&r.name) == host)
                    .chain(self.pending_addrs.get(&host).into_iter().flatten())
                    .chain(self.withheld_addrs.get(&host).into_iter().flatten())
                    // Live copies only, before the dedup and from every
                    // source: a stale copy (an earlier service's, or a
                    // pending one) must not shadow a live one.
                    .filter(|r| record_liveness(r) == RecordLiveness::Live)
                    .filter(|r| {
                        seen.insert((
                            r.rtype,
                            r.rdata.as_str(),
                            r.source,
                            r.iface.as_str(),
                            r.ifindex,
                        ))
                    })
                    .collect();
                anomalies::HostAddressView { host, records }
            })
            .collect()
    }

    /// Device names for source addresses (#246), from live A/AAAA
    /// records: service answers, enumeration rows, pending services,
    /// pending addresses and withheld (NSEC-denied) host addresses. Rebuilt on demand; never cached.
    pub fn address_book(&self) -> AddressBook {
        let host_keys = self
            .services
            .iter()
            .map(|s| Self::host_key(&s.hostname))
            .filter(|k| !k.is_empty())
            .collect();
        let mut book = AddressBook::new(host_keys);
        let records = self
            .services
            .iter()
            .flat_map(|s| s.answers.iter())
            .chain(self.enum_entries.iter().flat_map(|e| e.answers.iter()))
            .chain(self.pending_instances.iter().flat_map(|p| p.answers.iter()))
            .chain(self.pending_addrs.values().flatten())
            // Denied on every service (#245) but still the host's live
            // addresses: the host header shows them, so naming does too.
            .chain(self.withheld_addrs.values().flatten());
        for rec in records {
            book.add(rec);
        }
        book
    }

    /// Whether any live sighting has no owner (it would be filed under
    /// `anomalies::UNATTRIBUTED_SERVICE`). Cheap: no analyzer run.
    fn has_unattributed(&self) -> bool {
        let now = Instant::now();
        self.sightings
            .iter()
            .any(|s| s.is_live(now) && self.sighting_owners(s).is_empty())
    }

    /// Normalized group key for host grouping: lowercased hostname without
    /// trailing dot, `""` when the service has no hostname yet.
    /// Same normalization as `anomalies::host_id`, so a host group's
    /// key is also the owner id of its host-owned findings.
    fn host_key(hostname: &str) -> String {
        anomalies::host_id(hostname)
    }

    /// Display name for a host group key: first-seen hostname without its
    /// trailing dot or redundant `.local` suffix, or `(unknown host)` when
    /// no hostname is known yet. Grouping keys keep the full name; this
    /// is display-only.
    pub fn host_display_name(&self, key: &str) -> String {
        if key.is_empty() {
            return "(unknown host)".to_string();
        }
        if key == ENUM_HOST || key == UNATTRIBUTED_HOST {
            return key.to_string();
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
        browse::strip_local_suffix(name)
            .unwrap_or_else(|| name.trim_end_matches('.'))
            .to_string()
    }

    /// Live addresses (A/AAAA rdata) aggregated across all services on the
    /// host, deduped with IPv4 first. Expired rows are omitted.
    pub fn host_addresses(&self, key: &str) -> Vec<String> {
        let mut seen = HashSet::new();
        let mut v4 = Vec::new();
        let mut v6 = Vec::new();
        // Every target whose filed rows count here; withheld rows use the
        // same set.
        let mut all_targets: HashSet<String> = HashSet::from([key.to_string()]);
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
            all_targets.extend(targets.iter().cloned());
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
        // Addresses withheld from every service of this host by an NSEC
        // denial (#245) are still the host's own addresses.
        let withheld = all_targets
            .iter()
            .filter_map(|target| self.withheld_addrs.get(target))
            .flatten();
        for rec in withheld {
            if rec.ttl <= rec.received_at.elapsed().as_secs() as u32 {
                continue;
            }
            let ip = rec.rdata.trim().to_string();
            if ip.is_empty() || !seen.insert(ip.clone()) {
                continue;
            }
            if rec.rtype == 1 {
                v4.push(ip);
            } else {
                v6.push(ip);
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
        if key == UNATTRIBUTED_HOST {
            return 1;
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
    #[cfg(test)]
    pub fn metrics_rows(&self) -> Vec<(String, String)> {
        self.metrics_rows_in(&self.anomalies())
    }

    /// `metrics_rows` over a precomputed finding set (see
    /// `anomaly_counts_in`), so the overlay shares the frame's analyzer run.
    pub fn metrics_rows_in(&self, found: &[anomalies::Anomaly]) -> Vec<(String, String)> {
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
            "out-of-scope sightings / dropped",
            format!(
                "{} / {}",
                self.sightings.len(),
                self.metrics.sightings_dropped
            ),
        );
        let (tx_v4, tx_v6) = self.query_tx.transmit().flags();
        let state = |ok: bool| if ok { "ok" } else { "paused" };
        kv(
            &mut rows,
            "transmit",
            format!("v4 {} · v6 {}", state(tx_v4), state(tx_v6)),
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

        // Anomalies last: only the session-wide summary. Each finding
        // sits next to its owner in the main panes (#248), and `Ctrl+J`
        // dumps the full list.
        section(&mut rows, "Anomalies");
        // One question filed on several services is one finding here:
        // the overlay is session-wide, not per service.
        let collapsed = anomalies::collapse_questions(found);
        let errors = collapsed
            .iter()
            .filter(|(a, _)| matches!(a.severity, anomalies::Severity::Error))
            .count();
        let warnings = collapsed
            .iter()
            .filter(|(a, _)| matches!(a.severity, anomalies::Severity::Warning))
            .count();
        let infos = collapsed.len().saturating_sub(errors + warnings);
        kv(
            &mut rows,
            "summary",
            if collapsed.is_empty() {
                "none".to_string()
            } else {
                format!("{errors} error · {warnings} warning · {infos} info")
            },
        );

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

    /// Message-level decode failures: counted in the listener thread so
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
            if let Some(rtype) = browse::rtype_from_str(rtype_str) {
                out.push(anomalies::QuestionView {
                    service: service.clone(),
                    name,
                    rtype,
                    rtype_str,
                    source: *source,
                    // Questions rows carry no ingress link.
                    source_label: source.to_string(),
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
                denied_address_types: self.denied_types(&service_key(&s.instance, &s.service_type)),
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
                denied_address_types: self.denied_types(&service_key(&p.instance, &p.service_type)),
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
        // analyzer can attribute demand-side unicast-type questions the
        // same way it does answer sightings. Unrecognised type labels stay quiet.
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
        // Out-of-scope sightings: one analyzer entry per owner, resolved
        // now so later-appearing services claim earlier sightings.
        let now = Instant::now();
        let mut sightings = Vec::new();
        for s in self.sightings.iter().filter(|s| s.is_live(now)) {
            let mut owners = self.sighting_owners(s);
            if owners.is_empty() {
                owners.push(anomalies::UNATTRIBUTED_SERVICE.to_string());
            }
            for service in owners {
                match s.kind {
                    SightingKind::Question => questions.push(anomalies::QuestionView {
                        service,
                        name: &s.rec.name,
                        rtype: s.rec.rtype,
                        rtype_str: &s.rec.rtype_str,
                        source: s.rec.source,
                        source_label: s.rec.source_label(),
                    }),
                    SightingKind::Response | SightingKind::KnownAnswer => {
                        sightings.push((service, &s.rec))
                    }
                }
            }
        }
        let host_addresses = self.host_address_views();
        let book = self.address_book();
        let device_names = host_addresses
            .iter()
            .flat_map(|v| v.records.iter())
            .filter_map(|r| {
                let ip = r.source.ip();
                book.resolve(ip).map(|d| (ip, d.display()))
            })
            .collect();
        let snap = anomalies::Snapshot {
            services,
            enum_answers,
            pending_hosts,
            questions,
            sightings,
            host_addresses,
            device_names,
        };
        anomalies::analyze_observations(&snap, &self.raw_events, &address_queries)
    }

    /// Per-service anomaly counts keyed by `instance.service_type`
    /// service id. Used for host-list markers and the Answers table
    /// without recomputing per row. Informational notes never count.
    #[cfg(test)]
    pub fn anomaly_counts(&self) -> HashMap<String, usize> {
        Self::anomaly_counts_in(&self.anomalies())
            .into_iter()
            .map(|(owner, (n, _))| (owner, n))
            .collect()
    }

    /// `anomaly_counts` over a precomputed finding set, so a frame runs
    /// the analyzer once instead of once per pane.
    pub fn anomaly_counts_in(
        found: &[anomalies::Anomaly],
    ) -> HashMap<String, (usize, anomalies::Severity)> {
        // Every finding counts, info included (#248): each owner's badge
        // names how many findings sit next to it and the worst level.
        let mut counts: HashMap<String, (usize, anomalies::Severity)> = HashMap::new();
        for a in found {
            let entry = counts.entry(a.service.clone()).or_insert((0, a.severity));
            entry.0 += 1;
            if a.severity.rank() > entry.1.rank() {
                entry.1 = a.severity;
            }
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

    fn dump_answer_row(rec: &browse::RawRecord, book: &AddressBook) -> dump::DumpAnswer {
        let device = book.resolve(rec.source.ip());
        dump::DumpAnswer {
            source_names: device.as_ref().map(|d| d.names.clone()).unwrap_or_default(),
            source_name_inferred: device.as_ref().is_some_and(|d| d.inferred),
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

    fn dump_question_row(q: &QuestionRow, book: &AddressBook) -> dump::DumpQuestion {
        // Our own inferred sends stay `self`, unnamed.
        let device = (q.2 != SELF_SOURCE)
            .then(|| book.resolve(q.2.ip()))
            .flatten();
        dump::DumpQuestion {
            source_names: device.as_ref().map(|d| d.names.clone()).unwrap_or_default(),
            source_name_inferred: device.as_ref().is_some_and(|d| d.inferred),
            name: q.0.clone(),
            rtype_str: q.1.clone(),
            source: if q.2 == SELF_SOURCE {
                SELF_SOURCE_LABEL.to_string()
            } else {
                q.2.to_string()
            },
            received_at: dump::instant_to_iso(q.3),
            age_secs: q.3.elapsed().as_secs(),
        }
    }

    fn dump_service(&self, svc: &ServiceEntry, book: &AddressBook) -> dump::DumpService {
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
                .map(|r| Self::dump_answer_row(r, book))
                .collect(),
            questions: svc
                .questions
                .iter()
                .map(|q| Self::dump_question_row(q, book))
                .collect(),
            questions_truncated: svc.questions_dropped > 0,
            questions_dropped: svc.questions_dropped,
            address_denials: self.dump_denials(&service_key(&svc.instance, &svc.service_type)),
        }
    }

    /// Live address denials of one service, for the dump (#245).
    fn dump_denials(&self, service: &str) -> Vec<dump::DumpDenial> {
        self.address_denials
            .iter()
            .filter(|d| d.service == service && d.is_live())
            .map(|d| dump::DumpDenial {
                rtype_str: browse::rtype_label(d.rtype),
                form: d.form.as_str().to_string(),
                host: d.host.clone(),
                source: d.source.to_string(),
                ttl_remaining_secs: u64::from(d.ttl)
                    .saturating_sub(d.received_at.elapsed().as_secs()),
            })
            .collect()
    }

    /// Snapshot of mex's own browse state.
    fn state_dump(&self) -> dump::StateDump {
        let book = self.address_book();
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
        let (tx_v4, tx_v6) = self.query_tx.transmit().flags();
        metrics.insert("transmit_v4".to_string(), u64::from(tx_v4));
        metrics.insert("transmit_v6".to_string(), u64::from(tx_v6));
        metrics.insert("sightings_current".to_string(), self.sightings.len() as u64);
        metrics.insert("sightings_dropped".to_string(), m.sightings_dropped);
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
        let all = self.anomalies();
        // The dump is session-wide: a question filed on several services
        // is listed once, naming the other services in `also_services`.
        let found = anomalies::collapse_questions(&all);
        metrics.insert("anomalies_total".to_string(), found.len() as u64);
        metrics.insert(
            "anomalies_error".to_string(),
            found
                .iter()
                .filter(|(a, _)| matches!(a.severity, anomalies::Severity::Error))
                .count() as u64,
        );
        metrics.insert(
            "anomalies_warning".to_string(),
            found
                .iter()
                .filter(|(a, _)| matches!(a.severity, anomalies::Severity::Warning))
                .count() as u64,
        );
        metrics.insert(
            "malformed_packets".to_string(),
            self.drop_stats.malformed_total(),
        );
        dump::StateDump {
            metadata: dump::Metadata {
                dump_timestamp: dump::dump_timestamp_iso(),
                application_name: crate::APP_NAME.to_string(),
                version: env!("CARGO_PKG_VERSION").to_string(),
            },
            services: self
                .services
                .iter()
                .map(|s| self.dump_service(s, &book))
                .collect(),
            service_types,
            metrics,
            passive: self.passive,
            enum_groups: self
                .enum_entries
                .iter()
                .map(|e| dump::RawGroup {
                    name: e.name.clone(),
                    answers: e
                        .answers
                        .iter()
                        .map(|r| Self::dump_answer_row(r, &book))
                        .collect(),
                    questions: e
                        .questions
                        .iter()
                        .map(|q| Self::dump_question_row(q, &book))
                        .collect(),
                    questions_truncated: e.questions_dropped > 0,
                    questions_dropped: e.questions_dropped,
                })
                .collect(),
            pending: self
                .pending_instances
                .iter()
                .map(|p| dump::RawGroup {
                    name: format!("{}.{}", p.instance, p.service_type),
                    answers: p
                        .answers
                        .iter()
                        .map(|r| Self::dump_answer_row(r, &book))
                        .collect(),
                    questions: p
                        .questions
                        .iter()
                        .map(|q| Self::dump_question_row(q, &book))
                        .collect(),
                    questions_truncated: p.questions_dropped > 0,
                    questions_dropped: p.questions_dropped,
                })
                .collect(),
            interests,
            question_window_secs: QUESTION_WINDOW.as_secs(),
            anomalies: found
                .iter()
                .map(|(a, also)| {
                    let device = a.source.as_deref().and_then(|s| book.resolve_label(s));
                    dump::DumpAnomaly {
                        source_names: device.as_ref().map(|d| d.names.clone()).unwrap_or_default(),
                        source_name_inferred: device.as_ref().is_some_and(|d| d.inferred),
                        kind: a.kind.as_str().to_string(),
                        severity: a.severity.as_str().to_string(),
                        service: a.service.clone(),
                        also_services: also.iter().map(|s| s.to_string()).collect(),
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
                        responders: a
                            .responders
                            .iter()
                            .map(|r| dump::DumpResponder {
                                sources: r.sources.clone(),
                                name: r.name.clone(),
                                // Same safe-sharing policy as AAAA rdata.
                                addresses: r
                                    .addresses
                                    .iter()
                                    .map(|addr| dump::redact_ip_literal(addr))
                                    .collect(),
                            })
                            .collect(),
                        // The conflict message spells out the addresses:
                        // mask public IPv6 there too, word by word.
                        message: if a.responders.is_empty() {
                            a.message.clone()
                        } else {
                            dump::redact_ip_words(&a.message)
                        },
                        rfc: a.rfc.to_string(),
                        requirement: a.requirement.to_string(),
                        section: a.response.as_ref().map(|r| r.section.as_str().to_string()),
                        in_response_to: a
                            .response
                            .as_ref()
                            .and_then(|r| r.trigger.as_ref())
                            .map(|t| t.question.clone()),
                        in_response_to_own: a
                            .response
                            .as_ref()
                            .and_then(|r| r.trigger.as_ref())
                            .map(|t| t.own),
                    }
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
            Some(DisplayItem::Unattributed) => {
                let label = UNATTRIBUTED_HOST.to_string();
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

    /// Mark selection-relevant state as changed (see `state_gen`).
    fn touch(&mut self) {
        self.state_gen = self.state_gen.wrapping_add(1);
    }

    fn handle_key(&mut self, key: &KeyEvent) {
        self.touch();
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
                    Focus::Questions => Focus::Hex,
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
                    Focus::Hex => Focus::Questions,
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

    /// Answers/Questions shares keep at least 10% each and leave at least
    /// 10% for the hex pane (`answers + questions <= 90`). The second
    /// argument is the other share.
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
    /// / Questions top, then Questions bottom / Hex top horizontally.
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
        if answers.height > 0 && questions.height > 0 {
            let bottom = answers.y.saturating_add(answers.height.saturating_sub(1));
            if (row == bottom || row == questions.y)
                && col >= answers.x
                && col < answers.x.saturating_add(answers.width)
            {
                return DragMode::HorizUpper;
            }
        }
        let hex = self.hex_rect.get();
        if questions.height > 0 && hex.height > 0 {
            let bottom = questions
                .y
                .saturating_add(questions.height.saturating_sub(1));
            if (row == bottom || row == hex.y)
                && col >= questions.x
                && col < questions.x.saturating_add(questions.width)
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
        self.answers_pct = Self::clamp_pane_pct(pct, self.questions_pct);
    }

    fn set_questions_from_y(&mut self, row: u16) {
        let combined = Self::pct_from_y(row, self.right_rect.get());
        let want = combined.saturating_sub(self.answers_pct);
        self.questions_pct = Self::clamp_pane_pct(want, self.answers_pct);
    }

    fn handle_mouse(&mut self, mouse: &MouseEvent) {
        self.touch();
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
            DragMode::HorizLower => {
                self.set_questions_from_y(row);
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
            DisplayItem::Instance { .. } | DisplayItem::Enum { .. } | DisplayItem::Unattributed => {
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
        // Finding and TXT child rows select their parent record, info and
        // block rows nothing. Hit-test the frame as drawn: findings can
        // change between drawing and the click.
        if let Some(rows) = self.answers_rows.borrow().as_ref() {
            return rows.get(table_row).copied().flatten();
        }
        // Nothing drawn for this target yet: the current layout.
        let target = self.display_detail()?;
        let found = self.anomalies();
        self.answers_layout(&target, &found)
            .get(table_row)?
            .owning_record()
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
            // restarts the hex dump at the top.
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
        // Each question row is followed by its finding rows (#248); hit
        // the frame as drawn, else the current layout.
        let drawn = self
            .questions_rows
            .borrow()
            .as_ref()
            .map(|rows| rows.get(table_row).copied().flatten());
        let hit = drawn.unwrap_or_else(|| {
            let found = self.anomalies();
            let mut row = 0;
            for (q, findings) in self.question_findings(&target, &found).iter().enumerate() {
                if (row..=row + findings.len()).contains(&table_row) {
                    return Some(q);
                }
                row += 1 + findings.len();
            }
            None
        });
        if let Some(question) = hit {
            self.detail_free_scroll = false;
            let idx = raws + question;
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
            // The hex pane has no cursor; its keys scroll the dump, which
            // follows the record cursor.
            Focus::Hex => match key.code {
                KeyCode::Up | KeyCode::Char('k') => self.scroll_hex(-1),
                KeyCode::Down | KeyCode::Char('j') => self.scroll_hex(1),
                KeyCode::Home => self.scroll_hex_edge(true),
                KeyCode::End => self.scroll_hex_edge(false),
                KeyCode::PageUp | KeyCode::Char('b') => self.page_hex(-1),
                KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => self.page_hex(1),
                _ => {}
            },
        }
    }

    /// Selectable stops for Up/Down: instances always, host
    /// headers only while collapsed (so a collapsed host can be
    /// uncollapsed again; folding is also available from member rows).
    fn is_selectable(&self, item: &DisplayItem) -> bool {
        match item {
            DisplayItem::Instance { .. } | DisplayItem::Enum { .. } | DisplayItem::Unattributed => {
                true
            }
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
            DisplayItem::Unattributed => Some(UNATTRIBUTED_HOST.to_string()),
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
                DisplayItem::Unattributed => label == UNATTRIBUTED_HOST,
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
        // Entries can vanish between frames on time alone (an expiring
        // `(unattributed)` group): never index past the rebuilt list.
        let mut cur = self.selected_display.min(max);

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
    /// record cursor; it spans everything. Hex has no cursor rows.
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
            Focus::Hex => (0, 0),
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
        // New row means new hex bytes: restart the dump at the top.
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
        // New row means new hex bytes: restart the dump at the top.
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

    /// Scroll the focused detail viewport: the Hex dump while it holds
    /// focus, otherwise the Answers table (which also scrolls from the
    /// Services and Questions panes).
    fn scroll_focused_detail(&mut self, delta: isize) {
        if self.focus == Focus::Hex {
            self.scroll_hex(delta);
        } else {
            self.scroll_detail(delta);
        }
    }

    /// Nudge a cursorless viewport offset, saturating at zero. Upper
    /// clamping happens at render time, where the line count is known.
    /// Shared by the Hex and metrics panes.
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

    /// New detail row: restart the hex dump at the top.
    fn restart_for_new_row(&mut self) {
        self.hex_offset.set(0);
        self.hex_selected_field.set(None);
        self.hex_field_hits.borrow_mut().clear();
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
                ifindex: r.ifindex,
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
                ifindex,
            } => raws.iter().position(|r| {
                &r.name == name
                    && r.rtype == *rtype
                    && &r.rdata == rdata
                    && r.source == *source
                    && r.ifindex == *ifindex
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
        let unattributed = self.unattributed_selected();
        if svc_key.is_none() && enum_key.is_none() && !unattributed {
            // Headers select no row: no field stays highlighted.
            self.hex_selected_field.set(None);
            self.hex_field_hits.borrow_mut().clear();
            return;
        }
        if self.detail_svc_key != svc_key
            || self.detail_enum_key != enum_key
            || self.detail_unattributed != unattributed
        {
            self.detail_svc_key = svc_key;
            self.detail_enum_key = enum_key;
            self.detail_unattributed = unattributed;
            // The drawn row maps belong to the old target.
            self.answers_rows.replace(None);
            self.questions_rows.replace(None);
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
        self.touch();
        // RFC 6762 §18.11: messages received with a non-zero RCODE MUST be
        // silently ignored. The raw packet stays in the packet log for
        // inspection, but none of its records or questions reach state.
        if has_nonzero_rcode(ev) {
            log::debug!(
                "mex: ignoring response from {} with RCODE {:?}",
                ev.source,
                ev.rcode
            );
            return;
        }
        log::trace!(
            "mex: ingesting packet from {} ({} answer(s), {} question(s))",
            ev.source,
            ev.answers.len(),
            ev.questions.len()
        );
        // Denials first: the filing gate then keeps this packet's own
        // address additionals off a denying service, with no side effects
        // (e.g. cache-flush damping) for rows it never keeps.
        self.ingest_address_denials(ev);
        // NSEC rows go last, so an NSEC placed before its SRV in the
        // packet still finds the service that SRV creates.
        let (others, nsecs): (Vec<_>, Vec<_>) = ev.answers.iter().partition(|r| r.rtype != 47);
        for rec in others.into_iter().chain(nsecs) {
            // Out-of-scope types never become rows: they are kept only as
            // sightings behind findings, goodbyes included.
            if !anomalies::is_mdns_answer_type(rec.rtype) {
                // Remember the question that most likely triggered the
                // record, so findings can tell a reply to our own query
                // from one to someone else's.
                let mut rec = rec.clone();
                rec.trigger = self.response_trigger(&rec);
                self.ingest_sighting(SightingKind::Response, rec);
                continue;
            }
            if rec.ttl == 0 {
                self.mark_goodbye(rec);
                self.ingest_goodbye(rec, ev);
                continue;
            }
            self.ingest_record(rec, ev);
        }
        for q in &ev.questions {
            if !anomalies::is_mdns_question_type(q.rtype) {
                // Provenance still notes the ask, so a response it
                // triggers can name it.
                self.note_observed(q, ev);
                self.ingest_sighting(SightingKind::Question, q.clone());
                continue;
            }
            self.note_overheard(q, ev);
            self.route_question(q, ev);
        }
        // Out-of-scope known answers are beliefs, not facts, but still
        // out-of-scope data on the wire: sighted, never filed as rows.
        for ka in &ev.query_kas {
            if !anomalies::is_mdns_answer_type(ka.rtype) {
                self.ingest_sighting(SightingKind::KnownAnswer, ka.clone());
            }
        }
    }

    /// Lowercased keys of every live and pending service instance.
    fn live_service_keys(&self) -> HashSet<String> {
        self.services
            .iter()
            .map(|s| service_key(&s.instance, &s.service_type))
            .chain(
                self.pending_instances
                    .iter()
                    .map(|p| service_key(&p.instance, &p.service_type)),
            )
            .collect()
    }

    /// Apply NSEC address denials in a response (#245). Each NSEC states
    /// the full set of types at its owner, so it both adds and lifts:
    /// * RFC form: a hostname-owned NSEC in the same packet as a
    ///   service's SRV for that host denies the address types absent
    ///   from its bitmap and lifts those present, for that service and
    ///   host only;
    /// * legacy form: an instance-owned NSEC whose bitmap holds only A
    ///   and/or AAAA denies the listed types and lifts the others; any
    ///   other instance NSEC (the compliant SRV/TXT form) lifts them all;
    /// * a TTL-0 NSEC withdraws every denial its owner made, with or
    ///   without an SRV in the packet.
    fn ingest_address_denials(&mut self, ev: &browse::Event) {
        let srvs: Vec<(String, String)> = ev
            .answers
            .iter()
            .filter(|r| r.rtype == 33 && r.ttl > 0)
            .filter_map(|r| {
                let target = srv_target(&r.rdata)?.to_lowercase();
                Some((r.name.trim_end_matches('.').to_lowercase(), target))
            })
            .collect();
        // This packet's SRVs name instances too (they are filed next).
        let mut instances = self.live_service_keys();
        instances.extend(srvs.iter().map(|(service, _)| service.clone()));
        // ...and so do its PTR targets and TXT owners (an instance NSEC
        // can arrive with the PTR before any SRV).
        for r in ev.answers.iter().filter(|r| r.ttl > 0) {
            match r.rtype {
                12 if !is_enum_name(r.name.trim_end_matches('.')) => {
                    instances.insert(r.rdata.trim_end_matches('.').to_lowercase());
                }
                16 => {
                    instances.insert(r.name.trim_end_matches('.').to_lowercase());
                }
                _ => {}
            }
        }
        for nsec in ev.answers.iter().filter(|r| r.rtype == 47) {
            let owner = nsec.name.trim_end_matches('.').to_lowercase();
            let (address, other) = browse::nsec_address_types(&nsec.rdata);
            let denial =
                |service: &str, rtype: u16, host: Option<&str>, form: DenialForm| AddressDenial {
                    service: service.to_string(),
                    rtype,
                    host: host.map(str::to_string),
                    form,
                    source: nsec.source,
                    ttl: nsec.ttl,
                    received_at: nsec.received_at,
                };
            if nsec.ttl == 0 {
                // Goodbye: lift whatever this owner denied, anywhere.
                let before = self.address_denials.len();
                self.address_denials.retain(|d| {
                    d.host.as_deref() != Some(owner.as_str())
                        && !(d.host.is_none() && d.service == owner)
                });
                if self.address_denials.len() != before {
                    self.touch();
                }
                continue;
            }
            for (service, _) in srvs.iter().filter(|(_, target)| *target == owner) {
                for rtype in [1, 28] {
                    let d = denial(service, rtype, Some(&owner), DenialForm::Rfc);
                    if address.contains(&rtype) {
                        self.lift_denial(&d);
                    } else {
                        self.apply_denial(d);
                    }
                }
            }
            if instances.contains(&owner) {
                let inverted = !address.is_empty() && !other;
                for rtype in [1, 28] {
                    let d = denial(&owner, rtype, None, DenialForm::Legacy);
                    if inverted && address.contains(&rtype) {
                        self.apply_denial(d);
                    } else {
                        self.lift_denial(&d);
                    }
                }
            }
        }
    }

    /// Drop any denial with the same identity (service, type, host).
    fn lift_denial(&mut self, denial: &AddressDenial) {
        let before = self.address_denials.len();
        self.address_denials.retain(|d| {
            !(d.service == denial.service && d.rtype == denial.rtype && d.host == denial.host)
        });
        if self.address_denials.len() != before {
            self.touch();
        }
    }

    /// Record (or refresh) one denial, and take matching address rows
    /// back off its service.
    fn apply_denial(&mut self, denial: AddressDenial) {
        self.lift_denial(&denial);
        // An NSEC already past its TTL denies nothing: never take live
        // rows away for it.
        if !denial.is_live() {
            return;
        }
        log::debug!(
            "mex: {} denies {} via NSEC ({} form, from {})",
            denial.service,
            browse::rtype_label(denial.rtype),
            denial.form.as_str(),
            denial.source
        );
        if let Some(svc) = self
            .services
            .iter_mut()
            .find(|s| service_key(&s.instance, &s.service_type) == denial.service)
        {
            let mut withheld = Vec::new();
            svc.answers.retain(|r| {
                let owner = r.name.trim_end_matches('.').to_lowercase();
                let denied = denial.applies_to(r.rtype, &owner);
                if denied {
                    withheld.push(r.clone());
                }
                !denied
            });
            for rec in withheld {
                self.withhold_address(&rec);
            }
        }
        self.address_denials.push(denial);
        self.touch();
    }

    /// Live denials of `service` as (address type, host or every host).
    fn denied_types(&self, service: &str) -> Vec<(u16, Option<String>)> {
        self.address_denials
            .iter()
            .filter(|d| d.service == service && d.is_live())
            .map(|d| (d.rtype, d.host.clone()))
            .collect()
    }

    /// Whether a live denial keeps this address row off `service`.
    fn address_denied(&self, service: &str, rec: &browse::RawRecord) -> bool {
        matches!(rec.rtype, 1 | 28) && {
            let host = rec.name.trim_end_matches('.').to_lowercase();
            self.address_denials
                .iter()
                .any(|d| d.covers(service, rec.rtype, &host))
        }
    }

    /// Drop a withheld copy of `rec` (same type, address, source).
    fn forget_withheld(&mut self, rec: &browse::RawRecord) {
        let host = rec.name.trim_end_matches('.').to_lowercase();
        if let Some(rows) = self.withheld_addrs.get_mut(&host) {
            rows.retain(|r| {
                !(r.rtype == rec.rtype
                    && r.rdata == rec.rdata
                    && r.source == rec.source
                    && r.ifindex == rec.ifindex)
            });
            if rows.is_empty() {
                self.withheld_addrs.remove(&host);
            }
        }
    }

    /// Keep an address no service may show, so its host header still
    /// lists it (deduplicated like rows: type, address, source).
    fn withhold_address(&mut self, rec: &browse::RawRecord) {
        let host = rec.name.trim_end_matches('.').to_lowercase();
        let rows = self.withheld_addrs.entry(host).or_default();
        rows.retain(|r| {
            !(r.rtype == rec.rtype
                && r.rdata == rec.rdata
                && r.source == rec.source
                && r.ifindex == rec.ifindex)
        });
        if rec.ttl > 0 {
            rows.push(rec.clone());
        }
    }

    /// Hostnames a service lives on, lowercased without the root dot:
    /// every live SRV target. The selected hostname alone is no evidence:
    /// it outlives an expired SRV while the PTR is still live.
    pub(crate) fn service_hosts(svc: &ServiceEntry) -> Vec<String> {
        let mut hosts = Vec::new();
        for r in &svc.answers {
            if r.rtype != 33 || r.ttl <= r.received_at.elapsed().as_secs() as u32 {
                continue;
            }
            if let Some(target) = srv_target(&r.rdata) {
                let target = anomalies::host_id(target);
                if !hosts.contains(&target) {
                    hosts.push(target);
                }
            }
        }
        hosts
    }

    /// Finding owners for an out-of-scope record or question:
    /// * enumeration names belong to the enumeration row;
    /// * an instance name belongs to that live or pending service
    ///   (questions also match the service type, like `route_question`);
    /// * a hostname any live service lives on belongs to the host
    ///   itself (`anomalies::host_id`), once, not to each service on it.
    ///
    /// Empty when nothing matches.
    fn sighting_owners(&self, sighting: &Sighting) -> Vec<String> {
        let name = sighting.rec.name.trim_end_matches('.').to_lowercase();
        let question = sighting.kind == SightingKind::Question;
        if is_enum_name(&name) {
            return vec![anomalies::ENUMERATION_SERVICE.to_string()];
        }
        let mut owners: Vec<String> = Vec::new();
        let mut add = |id: String| {
            if !owners.contains(&id) {
                owners.push(id);
            }
        };
        for svc in &self.services {
            let full = format!("{}.{}", svc.instance, svc.service_type).to_lowercase();
            if full == name || (question && svc.service_type.to_lowercase() == name) {
                add(anomalies::service_id(&svc.instance, &svc.service_type));
            }
            if Self::service_hosts(svc).contains(&name) {
                add(anomalies::host_id(&name));
            }
        }
        for p in &self.pending_instances {
            let full = format!("{}.{}", p.instance, p.service_type).to_lowercase();
            if full == name || (question && p.service_type.to_lowercase() == name) {
                add(anomalies::service_id(&p.instance, &p.service_type));
            }
        }
        owners
    }

    /// File an out-of-scope record or question as a sighting. A TTL-0
    /// response record withdraws its sighting instead (it never reaches
    /// the goodbye paths, so no real answer row is marked gone); a
    /// known answer is never a goodbye. Re-filing moves the sighting to
    /// the back, so the cap evicts the one seen least recently.
    fn ingest_sighting(&mut self, kind: SightingKind, rec: browse::RawRecord) {
        if kind == SightingKind::Response && rec.ttl == 0 {
            let before = self.sightings.len();
            self.sightings.retain(|s| !s.same_record(kind, &rec));
            if self.sightings.len() != before {
                self.touch();
            }
            return;
        }
        self.sightings.retain(|s| !s.same_identity(kind, &rec));
        self.sightings.push(Sighting { kind, rec });
        if self.sightings.len() > SIGHTINGS_CAP {
            self.sightings.remove(0);
            self.metrics.sightings_dropped += 1;
        }
        self.touch();
    }

    /// The question a response record most likely answered: the latest
    /// question for its owner name, any type, ours (transmitted) or a
    /// remote querier's (observed), at most `TRIGGER_WINDOW` before the
    /// record arrived. mDNS responses carry no question section
    /// (RFC 6762 §6), so timing is all there is. Provenance keeps only the
    /// latest timestamp per interest, which is why this runs at ingest.
    fn response_trigger(&self, rec: &browse::RawRecord) -> Option<browse::QueryTrigger> {
        let name = Self::provenance_key(&rec.name, rec.rtype).0;
        self.query_history
            .iter()
            .filter(|((n, _), _)| *n == name)
            .flat_map(|((_, rtype), state)| {
                [
                    (state.transmitted, true),
                    (state.observed.as_ref().map(|o| o.at), false),
                ]
                .into_iter()
                .filter_map(move |(at, own)| at.map(|at| (at, own, *rtype)))
            })
            .filter(|(at, _, _)| {
                *at <= rec.received_at && rec.received_at.duration_since(*at) <= TRIGGER_WINDOW
            })
            .max_by_key(|(at, _, _)| *at)
            .map(|(_, own, rtype)| browse::QueryTrigger {
                question: format!(
                    "{}. {}",
                    rec.name.trim_end_matches('.'),
                    browse::rtype_label(rtype)
                ),
                own,
            })
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
    /// Whether a live unique (cache-flush) answer for `key` is cached and
    /// still before its 80%-TTL refresh window.
    fn has_fresh_unique_answer(&self, key: &(String, u16)) -> bool {
        self.services.iter().flat_map(|s| &s.answers).any(|r| {
            if !r.flush_bit
                || r.ttl == 0
                || r.rtype != key.1
                || r.name.trim_end_matches('.').to_lowercase() != key.0
            {
                return false;
            }
            let elapsed = r.received_at.elapsed().as_secs() as u32;
            !in_refresh_window(elapsed, r.ttl)
        })
    }

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
                        && r.ifindex == rec.ifindex
                }) {
                    entry.answers[pos] = rec.clone();
                } else {
                    entry.answers.push(rec.clone());
                }
            }
            return;
        }
        // An address still waiting for its service is withdrawn too: the
        // same (type, rdata, source) identity `handle_addr` updates by,
        // so a responder only withdraws its own announcement.
        if matches!(rec.rtype, 1 | 28) {
            let host = rec.name.trim_end_matches('.').to_lowercase();
            if let Some(records) = self.pending_addrs.get_mut(&host) {
                for pending in records.iter_mut().filter(|p| {
                    p.rtype == rec.rtype
                        && p.rdata == rec.rdata
                        && p.source == rec.source
                        && p.ifindex == rec.ifindex
                }) {
                    *pending = rec.clone();
                }
            }
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
    /// (name, type, source) asks again. Caps the list at `QUESTION_CAP`
    /// rows (the window ages rows out separately, in `evict_expired`).
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
                if rows.len() <= QUESTION_CAP {
                    return false;
                }
                // Rows already past the window would age out on the next
                // expiry pass anyway: drop them first, uncounted, so they
                // never cost a live row its slot.
                let now = Instant::now();
                rows.retain(|q| now.saturating_duration_since(q.3) <= QUESTION_WINDOW);
                if rows.len() <= QUESTION_CAP {
                    return false;
                }
                // Still full of live rows: evict the stalest by seen-at, not
                // the first in the list (a re-ask refreshes in place, so the
                // front row can be the freshest).
                if let Some(stalest) = rows
                    .iter()
                    .enumerate()
                    .min_by_key(|(_, q)| q.3)
                    .map(|(i, _)| i)
                {
                    rows.remove(stalest);
                }
                true
            }
        }
    }

    /// File a question we sent ourselves, inferred from the send path:
    /// the listener drops our own looped-back copies, so our transmissions
    /// never arrive as events. Store a minimal query packet for the question fields rather
    /// than reusing unrelated latest-event bytes. Filed for real sends and
    /// §7.3 suppressions alike: both are browse demand. Discovery sends
    /// precede the service, so matching pending instances park them until
    /// `handle_srv` moves them over on promotion. Passive mode sends nothing.
    fn route_own_question(&mut self, name: &str, rtype: u16, qu: bool) {
        // Display in the same fully-qualified form as observed questions
        // (`display_name` adds the root dot); match on the dot-less key.
        let bare = name.trim_end_matches('.');
        let display = format!("{bare}.");
        let key = bare.to_lowercase();
        // Only the types we ever transmit (`record_type_from_u16`) can
        // reach this path.
        let Some(label) = browse::record_type_from_u16(rtype).and(browse::rtype_name(rtype)) else {
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
                        && r.ifindex == rec.ifindex
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
                    elapsed <= r.ttl && in_refresh_window(elapsed, r.ttl)
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
            // Addresses withheld from every other service (all deny them)
            // are still live addresses of this host.
            let withheld: Vec<browse::RawRecord> = self
                .withheld_addrs
                .get(&host_key)
                .into_iter()
                .flatten()
                .filter(|r| r.ttl > r.received_at.elapsed().as_secs() as u32)
                .cloned()
                .collect();
            for r in backfill.iter().chain(&withheld) {
                self.push_record(idx, r);
            }
            // A cached copy filed on a sibling is not a network update: the
            // host keeps its own copy (the sibling may go away while the
            // others still deny the family).
            for r in &withheld {
                self.withhold_address(r);
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
                    && pending.ifindex == rec.ifindex
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

    /// In-scope records other than PTR/SRV/TXT/A/AAAA (NS, CNAME,
    /// HINFO, NSEC). One hostname backs many services: a host-owned
    /// record (e.g. HINFO) files on every service of that host, like
    /// addresses, not just the first.
    fn handle_other(&mut self, rec: &browse::RawRecord, ev: &browse::Event) {
        let name = rec.name.trim_end_matches('.').to_lowercase();
        let hits: Vec<usize> = self
            .services
            .iter()
            .enumerate()
            .filter(|(_, svc)| {
                // Instance name, selected hostname, or any live SRV target
                // (alternate targets own host records too, as for
                // addresses).
                format!("{}.{}", svc.instance, svc.service_type).to_lowercase() == name
                    || svc.hostname.trim_end_matches('.').to_lowercase() == name
                    || Self::service_hosts(svc).contains(&name)
            })
            .map(|(i, _)| i)
            .collect();
        for i in hits {
            self.services[i].last_event = Some(ev.clone());
            self.push_record(i, rec);
        }
        // An instance NSEC before the SRV: keep it on the pending
        // instance, which hands its rows over on promotion.
        if rec.rtype == 47 {
            for p in &mut self.pending_instances {
                let full = format!("{}.{}", p.instance, p.service_type).to_lowercase();
                if full != name {
                    continue;
                }
                p.answers.retain(|r| {
                    !(r.rtype == rec.rtype
                        && r.name.eq_ignore_ascii_case(&rec.name)
                        && r.source == rec.source
                        && r.ifindex == rec.ifindex)
                });
                p.answers.push(rec.clone());
                p.last_seen = Instant::now();
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
        // A denied address type stays off this service (#245); the host
        // header still lists it.
        let key = service_key(
            &self.services[svc_idx].instance,
            &self.services[svc_idx].service_type,
        );
        if self.address_denied(&key, rec) {
            self.withhold_address(rec);
            return;
        }
        // Filed normally: the service row is now the record's truth, so a
        // withheld copy (from before a denial lifted) must not outlive a
        // later goodbye or rdata change.
        if matches!(rec.rtype, 1 | 28) {
            self.forget_withheld(rec);
        }
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
        // Replace the stale copy of the same record (name, type, rdata,
        // source, link): per link, so one source heard on two links keeps
        // a row on each (#264).
        if let Some(pos) = s.answers.iter().position(|r| {
            r.name == rec.name
                && r.rtype == rec.rtype
                && r.rdata == rec.rdata
                && r.source == rec.source
                && r.ifindex == rec.ifindex
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
                elapsed <= r.ttl && in_refresh_window(elapsed, r.ttl)
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
        // Host-owned records (addresses, and e.g. HINFO for the host
        // name) say the host is alive, not the service. They never
        // reactivate, so a withdrawn service is still withdrawn here:
        // keep its original grace deadline.
        let host_owned = {
            let host = self.services[svc_idx].hostname.trim_end_matches('.');
            !host.is_empty() && rec.name.trim_end_matches('.').eq_ignore_ascii_case(host)
        };
        if withdrawn && (rec.rtype == 1 || rec.rtype == 28 || host_owned) {
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
                // Another live copy of the withdrawn record (another
                // source, or the same source on another link, #264) keeps
                // the service up: only this copy's row goes `bye`.
                let still_announced = svc.answers.iter().any(|r| {
                    r.rtype == rec.rtype
                        && r.name.eq_ignore_ascii_case(&rec.name)
                        && (rec.rtype != 12 || r.rdata.eq_ignore_ascii_case(&rec.rdata))
                        && !(r.source == rec.source && r.ifindex == rec.ifindex)
                        && record_liveness(r) == RecordLiveness::Live
                });
                if !still_announced {
                    svc.is_active = false;
                }
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
        // Withheld addresses live for their TTL.
        self.withheld_addrs.retain(|_, rows| {
            rows.retain(|r| r.ttl > 0 && r.received_at.elapsed().as_secs() <= u64::from(r.ttl));
            !rows.is_empty()
        });
        Self::expire_stale_services(&mut self.services);
        let before = self.services.len();
        self.services
            .retain(|s| s.is_active || now.duration_since(s.last_seen) < grace);
        let services_expired = before - self.services.len();
        self.metrics.services_expired_total += services_expired as u64;
        if services_expired > 0 {
            self.touch();
        }
        self.pending_instances
            .retain(|p| now.duration_since(p.last_seen) < grace);
        // Denials live for their NSEC's TTL and only while their service
        // (or pending instance) does: pruned after both were pruned, so a
        // returning instance never inherits a stale denial.
        let owners = self.live_service_keys();
        self.address_denials
            .retain(|d| d.is_live() && owners.contains(&d.service));
        // Questions rows age out once their querier stopped asking for
        // the question window (#238); not a drop, so no counter moves.
        let fresh = |q: &QuestionRow| now.saturating_duration_since(q.3) <= QUESTION_WINDOW;
        let mut aged = false;
        for rows in self
            .services
            .iter_mut()
            .map(|s| &mut s.questions)
            .chain(self.pending_instances.iter_mut().map(|p| &mut p.questions))
            .chain(self.enum_entries.iter_mut().map(|e| &mut e.questions))
        {
            let before = rows.len();
            rows.retain(fresh);
            aged |= rows.len() != before;
        }
        if aged {
            self.touch();
        }
        // Sightings live for their TTL (questions: a fixed window);
        // owners are resolved at analysis time, so expiry is time only.
        let before = self.sightings.len();
        self.sightings.retain(|s| s.is_live(now));
        if self.sightings.len() != before {
            self.touch();
        }
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
        let mut enum_rows_pruned = false;
        for entry in &mut self.enum_entries {
            let before = entry.answers.len();
            entry
                .answers
                .retain(|r| r.received_at.elapsed().as_secs() as u32 <= r.ttl.saturating_add(120));
            enum_rows_pruned |= entry.answers.len() != before;
        }
        if enum_rows_pruned {
            self.touch();
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
        // Cursor clamping walks the display list and re-sorts the detail
        // rows; skip it on idle ticks where nothing it reads has changed.
        if self.clamped_gen != Some(self.state_gen) {
            self.clamp_selection();
            self.clamped_gen = Some(self.state_gen);
        }
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
            self.sticky_unattributed = false;
        }
        if let Some(enum_key) = self.selected_enum().map(|e| e.name.clone()) {
            self.sticky_enum_key = Some(enum_key);
            self.sticky_key = None;
            self.sticky_unattributed = false;
        }
        if self.unattributed_selected() {
            self.sticky_unattributed = true;
            self.sticky_key = None;
            self.sticky_enum_key = None;
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

    fn txt_key(rec: &browse::RawRecord) -> TxtKey {
        (rec.name.clone(), rec.rdata.clone(), rec.source, rec.ifindex)
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
        if self.unattributed_selected() {
            return Some(DetailTarget::Unattributed);
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
        // Folding the group parks on its header; keep showing it while
        // it exists.
        if self.sticky_unattributed && self.has_unattributed() {
            return Some(DetailTarget::Unattributed);
        }
        None
    }

    /// Whether the Hosts cursor sits on the `(unattributed)` row.
    fn unattributed_selected(&self) -> bool {
        matches!(
            self.display_items().get(self.selected_display),
            Some(DisplayItem::Unattributed)
        )
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
            // No rows of its own: nothing for the cursor or hex pane.
            DetailTarget::Unattributed => return None,
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

    /// The Answers table for `target`, line by line (#248): derived info
    /// rows, then the `service` block (findings of this owner with no row
    /// of their own), one `host <name>` block per live SRV-target host
    /// with host-owned findings, then every record row followed by its
    /// findings and (expanded) TXT pairs. Gone rows carry no findings.
    /// The unattributed view groups its findings by name instead.
    pub fn answers_layout(
        &self,
        target: &DetailTarget<'_>,
        found: &[anomalies::Anomaly],
    ) -> Vec<AnswerLine> {
        let mut lines = Vec::new();
        let id = Self::detail_service_id(target);
        let own: Vec<&anomalies::Anomaly> = found.iter().filter(|a| a.service == id).collect();
        match target {
            DetailTarget::Service(svc) => {
                lines.push(AnswerLine::Info {
                    label: "srvc",
                    text: svc.service_type.clone(),
                });
                let mut seen = HashSet::new();
                for sub in svc.subtypes.iter().filter(|sub| seen.insert(*sub)) {
                    lines.push(AnswerLine::Info {
                        label: "subt",
                        text: anomalies::display_subtype(sub),
                    });
                }
            }
            DetailTarget::Enum(entry) => lines.push(AnswerLine::Info {
                label: "enum",
                text: entry.name.clone(),
            }),
            DetailTarget::Unattributed => {
                let mut names: Vec<String> = Vec::new();
                for a in &own {
                    let name = a.record_name.clone().unwrap_or_default();
                    if !names.iter().any(|n| n.eq_ignore_ascii_case(&name)) {
                        names.push(name);
                    }
                }
                names.sort_by_key(|n| n.to_lowercase());
                for name in names {
                    lines.push(AnswerLine::Block(name.clone()));
                    for a in own.iter().filter(|a| {
                        a.record_name
                            .as_deref()
                            .unwrap_or_default()
                            .eq_ignore_ascii_case(&name)
                    }) {
                        lines.push(AnswerLine::Finding {
                            anomaly: Box::new((*a).clone()),
                            record: None,
                        });
                    }
                }
                return lines;
            }
        }

        let answers = target.ordered_answers();
        let questions = target.ordered_questions();
        let mut placed = vec![false; own.len()];
        let mut row_findings: Vec<Vec<anomalies::Anomaly>> = vec![Vec::new(); answers.len()];
        for (i, rec) in answers.iter().enumerate() {
            if record_liveness(rec) != RecordLiveness::Live {
                continue;
            }
            for (j, a) in own.iter().enumerate() {
                if !a.kind.is_question() && finding_matches_record(a, rec) {
                    row_findings[i].push((*a).clone());
                    placed[j] = true;
                }
            }
        }
        for (name, rtype_str, source, _, _) in &questions {
            for (j, a) in own.iter().enumerate() {
                if finding_matches_question(a, name, rtype_str, source) {
                    placed[j] = true;
                }
            }
        }
        let rowless: Vec<&anomalies::Anomaly> = own
            .iter()
            .zip(&placed)
            .filter(|(_, placed)| !**placed)
            .map(|(a, _)| *a)
            .collect();
        if !rowless.is_empty() {
            let label = match target {
                DetailTarget::Enum(_) => "enumeration",
                _ => "service",
            };
            lines.push(AnswerLine::Block(label.to_string()));
            lines.extend(rowless.into_iter().map(|a| AnswerLine::Finding {
                anomaly: Box::new(a.clone()),
                record: None,
            }));
        }
        if let DetailTarget::Service(svc) = target {
            for host in Self::service_hosts(svc) {
                let host_findings: Vec<&anomalies::Anomaly> =
                    found.iter().filter(|a| a.service == host).collect();
                if host_findings.is_empty() {
                    continue;
                }
                lines.push(AnswerLine::Block(format!(
                    "host {}",
                    Self::short_hostname(&host)
                )));
                lines.extend(host_findings.into_iter().map(|a| AnswerLine::Finding {
                    anomaly: Box::new(a.clone()),
                    record: None,
                }));
            }
        }
        for (i, rec) in answers.iter().enumerate() {
            lines.push(AnswerLine::Record(i));
            lines.extend(
                row_findings[i]
                    .drain(..)
                    .map(|anomaly| AnswerLine::Finding {
                        anomaly: Box::new(anomaly),
                        record: Some(i),
                    }),
            );
            // Multi-pair TXT children only while expanded (a lone pair
            // is already the parent's rdata).
            if !(Self::is_expandable_txt(rec) && self.is_txt_expanded(rec)) {
                continue;
            }
            let mut seen_pair = HashSet::new();
            let mut pairs: Vec<&str> = rec
                .rdata
                .split("; ")
                .filter(|pair| !pair.is_empty() && seen_pair.insert(*pair))
                .collect();
            pairs.sort_by(|a, b| {
                let ka = a.split('=').next().unwrap_or(a);
                let kb = b.split('=').next().unwrap_or(b);
                ka.to_lowercase()
                    .cmp(&kb.to_lowercase())
                    .then_with(|| ka.cmp(kb))
                    .then_with(|| a.cmp(b))
            });
            if pairs.len() > 1 {
                let n = pairs.len();
                for (k, pair) in pairs.into_iter().enumerate() {
                    lines.push(AnswerLine::TxtPair {
                        record: i,
                        pair: pair.to_string(),
                        last: k + 1 == n,
                    });
                }
            }
        }
        lines
    }

    /// Findings shown under each Questions row of `target`, aligned with
    /// `ordered_questions` (#248).
    pub fn question_findings(
        &self,
        target: &DetailTarget<'_>,
        found: &[anomalies::Anomaly],
    ) -> Vec<Vec<anomalies::Anomaly>> {
        let id = Self::detail_service_id(target);
        target
            .ordered_questions()
            .iter()
            .map(|(name, rtype_str, source, _, _)| {
                found
                    .iter()
                    .filter(|a| a.service == id)
                    .filter(|a| finding_matches_question(a, name, rtype_str, source))
                    .cloned()
                    .collect()
            })
            .collect()
    }

    /// Service id owning a detail target, matching `Anomaly.service`.
    fn detail_service_id(target: &DetailTarget<'_>) -> String {
        match target {
            DetailTarget::Service(s) => anomalies::service_id(&s.instance, &s.service_type),
            DetailTarget::Enum(_) => anomalies::ENUMERATION_SERVICE.to_string(),
            DetailTarget::Unattributed => anomalies::UNATTRIBUTED_SERVICE.to_string(),
        }
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
mod tests;
