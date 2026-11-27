// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use denials::AddressDenials;
pub use layout::{DrawnRows, Layout};
use schedule::Scheduler;
use std::cell::Cell;
use std::collections::{HashMap, HashSet, VecDeque};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
pub use view_state::ViewState;

use anyhow::Result;
use crossterm::event::{
    self, Event, KeyCode, KeyEvent, KeyEventKind, KeyModifiers, MouseButton, MouseEvent,
    MouseEventKind,
};
use ratatui::layout::Rect;
use simple_dns::TYPE;

use crate::anomalies;
use crate::browse;
use crate::browse::ENUM_SERVICE;
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
/// copy, and the diagnostics counts so the three cannot disagree about
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

/// Identity of one expandable TXT row: per link, like every row (#264).
type TxtKey = (String, String, std::net::SocketAddr, u32);

/// Identity of a detail row (record or question), so the cursor and
/// clicks survive resorting of the table (TTL countdowns, re-announcements
/// and new questions constantly reshuffle rows; #413). Matches the dedup
/// identities used at ingest; resolve it with `App::position_of_detail`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DetailCursorKey {
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

impl DetailCursorKey {
    /// Identity of a record row.
    pub fn record(r: &browse::RawRecord) -> Self {
        Self::Record {
            name: r.name.clone(),
            rtype: r.rtype,
            rdata: r.rdata.clone(),
            source: r.source,
            ifindex: r.ifindex,
        }
    }

    /// Identity of a question row.
    pub fn question(name: &str, rtype: &str, source: std::net::SocketAddr) -> Self {
        Self::Question {
            name: name.to_string(),
            rtype: rtype.to_string(),
            source,
        }
    }

    /// Whether `r` is this record row, by the ingest identities: the
    /// owner name folds ASCII case (`push_record`), and so does a PTR
    /// target, a name (enum rows replace by `same_ptr_target`). Other
    /// rdata compares exactly (TXT data is case-sensitive).
    fn is_record(&self, r: &browse::RawRecord) -> bool {
        match self {
            Self::Record {
                name,
                rtype,
                rdata,
                source,
                ifindex,
            } => {
                r.name.eq_ignore_ascii_case(name)
                    && r.rtype == *rtype
                    && same_rdata(*rtype, &r.rdata, rdata)
                    && r.source == *source
                    && r.ifindex == *ifindex
            }
            Self::Question { .. } => false,
        }
    }

    /// Whether two identities name the same row, by the rules that
    /// resolve them: names fold ASCII case (`is_record`; question rows
    /// as in `file_question_row`).
    pub fn same_row(&self, other: &Self) -> bool {
        match (self, other) {
            (
                Self::Record {
                    name,
                    rtype,
                    rdata,
                    source,
                    ifindex,
                },
                Self::Record {
                    name: n,
                    rtype: t,
                    rdata: d,
                    source: s,
                    ifindex: i,
                },
            ) => {
                name.eq_ignore_ascii_case(n)
                    && rtype == t
                    && same_rdata(*rtype, rdata, d)
                    && source == s
                    && ifindex == i
            }
            (
                Self::Question {
                    name,
                    rtype,
                    source,
                },
                Self::Question {
                    name: n,
                    rtype: t,
                    source: s,
                },
            ) => name.eq_ignore_ascii_case(n) && rtype == t && source == s,
            _ => false,
        }
    }

    /// Whether this question row is `(name, rtype, source)`: the name
    /// folds ASCII case, as `file_question_row` files it.
    fn is_question(&self, name: &str, rtype: &str, source: std::net::SocketAddr) -> bool {
        match self {
            Self::Question {
                name: n,
                rtype: t,
                source: s,
            } => n.eq_ignore_ascii_case(name) && t == rtype && *s == source,
            Self::Record { .. } => false,
        }
    }
}

/// Whether two rdata strings of type `rtype` are the same row's: a PTR
/// target is a name and folds ASCII case, any other rdata is exact.
fn same_rdata(rtype: u16, a: &str, b: &str) -> bool {
    if rtype == 12 {
        a.eq_ignore_ascii_case(b)
    } else {
        a == b
    }
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
/// it on schedule, the user sent it by hand (`r`, #394), §7.3
/// suppression stood in for it, or a remote querier asked it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum QueryOrigin {
    Transmitted,
    Manual,
    Suppressed,
    Observed,
}

impl QueryOrigin {
    pub fn as_str(self) -> &'static str {
        match self {
            QueryOrigin::Transmitted => "transmitted",
            QueryOrigin::Manual => "manual",
            QueryOrigin::Suppressed => "suppressed",
            QueryOrigin::Observed => "observed",
        }
    }
}

/// One of our own query events, as `note_query` records it: a scheduled
/// transmit, a manual (`r`) transmit, or a §7.3 suppression. Observed
/// remote questions are not ours and go through `note_observed`, so
/// they cannot be passed here (#396).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum OwnQuery {
    Transmitted,
    Manual,
    Suppressed,
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
            QueryOrigin::Manual => s.manual,
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
    /// Instant of our last manual (`r`) query, if any. A manual send is
    /// also a transmit: when it equals `last_transmitted_at`, the
    /// latest transmit was the manual one.
    pub last_manual_at: Option<Instant>,
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
    /// Latest transmit, scheduled or manual.
    transmitted: Option<Instant>,
    transmitted_interfaces: String,
    /// Latest manual transmit (#394); also stamped into `transmitted`.
    manual: Option<Instant>,
    suppressed: Option<Instant>,
    observed: Option<ObservedQuery>,
}

impl InterestQueryState {
    /// Latest query event and its kind, if any.
    fn last(&self) -> Option<(QueryOrigin, Instant)> {
        [
            (QueryOrigin::Transmitted, self.transmitted),
            // After Transmitted: on the tie a manual send leaves (both
            // stamped), `max_by_key` keeps the later entry, Manual.
            (QueryOrigin::Manual, self.manual),
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

/// Group key of the selectable enumeration row in the Hosts pane. Ends
/// in a dot, which no host key does (`host_key` strips trailing dots):
/// a host named `(enumeration).` must never share this group.
pub const ENUM_HOST: &str = "(enumeration).";
/// Group key of the `(unattributed)` findings row in the Hosts pane,
/// present only while such findings exist; dotted like `ENUM_HOST`.
pub const UNATTRIBUTED_HOST: &str = "(unattributed).";
/// The names shown for the two built-in groups.
pub const ENUM_GROUP_NAME: &str = "(enumeration)";
pub const UNATTRIBUTED_GROUP_NAME: &str = "(unattributed)";

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
        browse::presentation_labels(&rec.name)
            .into_iter()
            .map(String::into_bytes)
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
        .map(|label| browse::escape_label(&String::from_utf8_lossy(label)))
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
/// Minimum gap between a manual query and any earlier send of the same
/// question (#394; RFC 6762 §5.2 spacing).
const MANUAL_REFRESH_SPACING: Duration = Duration::from_secs(1);
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
const DIAGNOSTICS_WINDOW: Duration = Duration::from_secs(300);

/// Bound on out-of-scope sightings, so a peer flooding distinct
/// unsupported records cannot grow state without limit. The oldest is
/// evicted first and counted in `DiagnosticsCounters::sightings_dropped`.
const SIGHTINGS_CAP: usize = 256;

/// Most distinct packet sources counted in `DiagnosticsCounters::source_rx`.
/// The overlay shows only the top talkers; the cap keeps spoofed or
/// churning source addresses from growing the map without bound.
const SOURCE_RX_CAP: usize = 256;
/// Our own sent query copies kept for the multicast-rate check (#431):
/// twice the 2000 retained packets, so a busy round of ours on several
/// links still covers the whole retained window.
const OWN_SENDS_CAP: usize = 4000;

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

/// Lowercased presentation-form service name (`browse::instance_name`,
/// instance label escaped), the identity address denials use.
fn service_key(instance: &str, service_type: &str) -> String {
    crate::browse::instance_name(instance, service_type).to_ascii_lowercase()
}

/// Cumulative v2 traffic/query counters for the diagnostics overlay. Derived
/// snapshot rows come from here plus live state; per-packet maps stay
/// bounded by network size (tens of responders/interfaces), and the
/// per-source map is capped at `SOURCE_RX_CAP` against spoofed sources.
#[derive(Debug, Default)]
pub struct DiagnosticsCounters {
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
    /// Queries sent by hand (`r` on a `self` question row).
    pub q_sent_manual: u64,
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
    /// Messages ignored for a non-zero OPCODE (RFC 6762 §18.3), and the
    /// last one's source and arrival.
    pub opcode_ignored: u64,
    pub opcode_ignored_last: Option<(std::net::SocketAddr, Instant)>,
}

impl DiagnosticsCounters {
    /// Count one packet from `src`. At `SOURCE_RX_CAP` distinct sources a
    /// new one evicts the quietest, so the busiest talkers stay exact.
    pub(super) fn count_source(&mut self, src: std::net::SocketAddr) {
        if !self.source_rx.contains_key(&src) && self.source_rx.len() >= SOURCE_RX_CAP {
            // At the cap the map is not empty, so a quietest source exists.
            let quietest = self
                .source_rx
                .iter()
                .min_by_key(|(_, count)| **count)
                .map(|(addr, _)| *addr);
            self.source_rx.retain(|addr, _| Some(*addr) != quietest);
        }
        *self.source_rx.entry(src).or_insert(0) += 1;
    }
}

/// What a terminal event asks of the TUI loop.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TerminalAction {
    /// Applied to the app state; keep going.
    Handled,
    /// Ctrl+Z: suspend the terminal (Unix only).
    #[cfg_attr(not(unix), allow(dead_code))]
    Suspend,
}

/// When the TUI redraws: only when something changed (input, new
/// packets, a log popup) or the wall-clock second ticked over (TTL
/// countdowns, ages, uptime, popup expiry). The 80 ms tick itself stays
/// for query scheduling; idle ticks skip the costly frame.
#[derive(Debug)]
struct RedrawGate {
    dirty: bool,
    drawn_sec: Option<u64>,
}

impl Default for RedrawGate {
    /// The first pass always draws.
    fn default() -> Self {
        Self {
            dirty: true,
            drawn_sec: None,
        }
    }
}

impl RedrawGate {
    /// Something shown may have changed.
    fn mark(&mut self) {
        self.dirty = true;
    }

    /// Whether a frame is due at wall-clock second `sec`.
    fn due(&self, sec: u64) -> bool {
        self.dirty || self.drawn_sec != Some(sec)
    }

    /// A frame was drawn at `sec`.
    fn drawn(&mut self, sec: u64) {
        self.dirty = false;
        self.drawn_sec = Some(sec);
    }
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
    services: Vec<ServiceEntry>,
    packet_count: u64,
    start_time: Instant,
    running: bool,
    /// Listen-only mode (`--passive`): never transmit queries.
    passive: bool,
    /// Explicit interface selection (`-i/--interfaces`): `None` browses
    /// all usable links; `Some` restricts joins, queries, and ingress to
    /// the named links. Local-address detection stays global.
    interfaces: Option<HashSet<String>>,
    /// Cumulative v2 counters (traffic, queries, suppressions).
    diagnostics: DiagnosticsCounters,
    /// Bumped by anything that can change the list or detail selection
    /// (ingest, eviction, input); `evict_expired` re-clamps the cursors
    /// only when it moved past `clamped_gen`, not on every idle tick.
    state_gen: u64,
    clamped_gen: Option<u64>,
    /// Cached usable/skipped link snapshot, refreshed on the 10s tick.
    link_stats: browse::LinkStats,
    /// Refused-packet accounting from the listener thread (RFC 6762 §11).
    drop_stats: Arc<browse::DropStats>,
    /// Where Ctrl+J writes state dumps: the working directory (empty
    /// path) unless a test points it elsewhere.
    state_dump_dir: std::path::PathBuf,

    rx: mpsc::Receiver<browse::Event>,
    /// Our own sent query copies, reported by the listener (#431).
    own_rx: mpsc::Receiver<browse::OwnSend>,
    /// The retained ones, in send order: no older than the second before
    /// the oldest retained packet, at most `OWN_SENDS_CAP`. Only the
    /// multicast-rate check reads them; they never displace a received
    /// packet.
    own_sends: Vec<browse::OwnSend>,
    query_tx: browse::QueryTx,
    /// Query scheduling state (RFC 6762 §5.2/§5.4/§7.1/§7.3); see
    /// [`Scheduler`].
    scheduler: Scheduler,
    last_ip_refresh: Instant,
    collapsed_hosts: HashSet<String>,
    /// Expanded TXT records in the Answers table, keyed by
    /// (name, rdata, source). Absent = collapsed (the default), so
    /// multi-pair TXT rows render as a single `▸ TXT` line until
    /// `Enter` expands them into `▾ TXT` plus child rows.
    expanded_txt: HashSet<TxtKey>,
    local_ips: HashSet<std::net::IpAddr>,
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
    /// Selectable enumeration row. Always present so our own enumeration
    /// demand has a home; answers and questions file here instead of
    /// being skipped as noise.
    enum_entries: Vec<EnumEntry>,
    pending_instances: Vec<PendingService>,
    pending_addrs: HashMap<String, Vec<browse::RawRecord>>,
    next_pending_addr_prune: Instant,
    raw_events: Vec<browse::Event>,
    /// Out-of-scope records and questions (`anomalies::is_mdns_answer_type`
    /// / `is_mdns_question_type` false), kept only as evidence for
    /// findings: never Answers or Questions rows, never query drivers.
    /// Oldest first, capped at `SIGHTINGS_CAP`.
    sightings: Vec<Sighting>,
    /// NSEC address denials (#245) and the addresses they withhold.
    address_denials: AddressDenials,
    /// Transient confirmation popup (e.g. state-dump result), shown for
    /// a few seconds and dismissed by any key.
    status_msg: Option<(String, Instant)>,
    /// Last-frame geometry and scroll offsets; see [`Layout`].
    layout: Layout,
    /// Focus, selection, pane splits and overlays; see [`ViewState`].
    view_state: ViewState,
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
/// cursor, one hex lookup, and one diagnostics definition.
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
            DetailTarget::Unattributed => UNATTRIBUTED_GROUP_NAME.to_string(),
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
    /// Focus, selection, pane splits and overlays; see [`ViewState`].
    pub fn view_state(&self) -> &ViewState {
        &self.view_state
    }

    /// Last-frame geometry and scroll offsets; see [`Layout`].
    pub fn layout(&self) -> &Layout {
        &self.layout
    }

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
        let (query_tx, rx, own_rx, drop_stats) = browse::spawn(interfaces.clone())?;
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
            view_state: ViewState::default(),
            layout: Layout::default(),
            passive,
            interfaces,
            services: Vec::new(),
            packet_count: 0,
            start_time: Instant::now(),
            running: true,
            rx,
            own_rx,
            own_sends: Vec::new(),
            query_tx,
            last_ip_refresh: Instant::now(),
            collapsed_hosts: HashSet::new(),
            expanded_txt: HashSet::new(),
            local_ips: browse::local_ips(),
            // The Answers pane holds finding child rows (#248): it gets
            // the larger share.
            detail_svc_key: None,
            detail_enum_key: None,
            detail_unattributed: false,
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
            address_denials: AddressDenials::default(),
            status_msg: None,
            diagnostics: DiagnosticsCounters::default(),
            scheduler: Scheduler::default(),
            state_gen: 0,
            clamped_gen: None,
            link_stats,
            drop_stats,
            state_dump_dir: std::path::PathBuf::new(),
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
        let mut redraw = RedrawGate::default();
        while self.running {
            if self.tick() {
                redraw.mark();
            }

            // Surface retained log write failures (terminal-safe: the
            // popup, not stderr, so the TUI is not corrupted).
            if let Some(msg) = crate::take_log_error() {
                self.show_status(msg);
                redraw.mark();
            }

            let sec = self.start_time.elapsed().as_secs();
            if redraw.due(sec) {
                terminal.draw(|f| ui::draw(f, self))?;
                redraw.drawn(sec);
            }

            if event::poll(Duration::from_millis(80))? {
                // Any input may change what is shown (keys, mouse hover,
                // resize): draw on the next pass.
                redraw.mark();
                // Drain everything pending so mouse drags stay smooth at
                // 12fps instead of handling one event per frame.
                loop {
                    let action = self.handle_terminal_event(event::read()?);
                    // Only Unix asks to suspend (Ctrl+Z).
                    #[cfg(unix)]
                    if action == TerminalAction::Suspend {
                        if !ui::suspend(terminal)? {
                            self.running = false;
                            return Ok(());
                        }
                        // Break out to redraw immediately: the inner loop
                        // would block on `read()` until the next input
                        // event, leaving the freshly cleared screen blank.
                        break;
                    }
                    #[cfg(not(unix))]
                    let _ = action;
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
        let mut logged_tens = 0;
        while self.running {
            self.tick();
            if let Some(line) = self.headless_progress(&mut logged_tens) {
                log::info!("{line}");
            }
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

    /// One pass of background work shared by both run loops: file new
    /// packets, send due queries, expire records. Returns whether new
    /// packets arrived (the TUI then redraws).
    fn tick(&mut self) -> bool {
        let packets_before = self.packet_count;
        self.drain_events();
        self.send_queries();
        self.evict_expired();
        self.packet_count != packets_before
    }

    /// Show `msg` in the status line (log write failures in the TUI).
    fn show_status(&mut self, msg: String) {
        self.status_msg = Some((msg, Instant::now()));
    }

    /// Progress line for the headless log, once per ten packets:
    /// `logged_tens` holds the tens already reported, so idle ticks stay
    /// quiet and a batch jumping past a multiple of ten still reports.
    fn headless_progress(&self, logged_tens: &mut u64) -> Option<String> {
        let tens = self.packet_count / 10;
        if tens <= *logged_tens {
            return None;
        }
        *logged_tens = tens;
        Some(format!(
            "mex: {} packets, {} services seen",
            self.packet_count,
            self.services.len()
        ))
    }

    /// Apply one terminal event. Only key presses count (releases and
    /// repeats are ignored). Unix suspend precedes all key handling
    /// (even the diagnostics overlay): raw mode delivers Ctrl+Z as a
    /// key event, not SIGTSTP, so the loop must suspend the terminal.
    fn handle_terminal_event(&mut self, event: Event) -> TerminalAction {
        match event {
            Event::Key(key) if key.kind == KeyEventKind::Press => {
                #[cfg(unix)]
                if Self::is_suspend_key(&key) {
                    return TerminalAction::Suspend;
                }
                self.handle_key(&key);
            }
            Event::Mouse(mouse) => self.handle_mouse(&mouse),
            Event::Resize(_, _) => self.touch(),
            _ => {}
        }
        TerminalAction::Handled
    }

    fn flush_pending_addrs(&mut self) {
        let mut services_by_host: HashMap<String, Vec<usize>> = HashMap::new();
        for (i, svc) in self.services.iter().enumerate() {
            let mut hosts = HashSet::new();
            let selected = svc.hostname.trim_end_matches('.').to_ascii_lowercase();
            if !selected.is_empty() {
                hosts.insert(selected);
            }
            for rec in &svc.answers {
                if rec.rtype != 33 || rec.ttl <= rec.received_at.elapsed().as_secs() as u32 {
                    continue;
                }
                if let Some(target) = srv_target(&rec.rdata) {
                    hosts.insert(target.to_ascii_lowercase());
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

    /// Take the listener's reports of our own sent copies, and keep
    /// only those a retained packet could answer: sent at most a second
    /// before the oldest one. With nothing retained yet, a reply may
    /// still come, so only the cap applies.
    fn drain_own_sends(&mut self) {
        while let Ok(sent) = self.own_rx.try_recv() {
            self.own_sends.push(sent);
        }
        if let Some(oldest) = self.raw_events.first() {
            let horizon = oldest.received_at.checked_sub(anomalies::MIN_GAP);
            let stale = self
                .own_sends
                .iter()
                .take_while(|s| horizon.is_some_and(|h| s.sent_at < h))
                .count();
            self.own_sends.drain(..stale);
        }
        if self.own_sends.len() > OWN_SENDS_CAP {
            self.own_sends.drain(..self.own_sends.len() - OWN_SENDS_CAP);
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
            .filter(|ev| !has_nonzero_rcode(ev) && !ev.is_ignored())
            .any(|ev| ev.answers.iter().any(|rec| rec.rtype == 33 && rec.ttl > 0));
        for ev in &batch {
            self.note_packet_diagnostics(ev);
            self.raw_events.push(ev.clone());
        }
        if self.raw_events.len() > 2000 {
            self.raw_events
                .drain(0..self.raw_events.len().saturating_sub(2000));
        }
        self.drain_own_sends();
        // Prune the sliding rate windows even on idle ticks.
        while self
            .diagnostics
            .packet_times
            .front()
            .is_some_and(|t| t.elapsed() > DIAGNOSTICS_WINDOW)
        {
            self.diagnostics.packet_times.pop_front();
        }
        while self
            .diagnostics
            .suppressed_times
            .front()
            .is_some_and(|t| t.elapsed() > DIAGNOSTICS_WINDOW)
        {
            self.diagnostics.suppressed_times.pop_front();
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

    /// Display key for an ingress link: the interface name, or the
    /// kernel index when the name never resolved.
    fn link_key(iface: &str, ifindex: u32) -> String {
        if iface.is_empty() {
            format!("if#{ifindex}")
        } else {
            iface.to_string()
        }
    }

    /// Re-read local addresses and per-link interface stats (the
    /// snapshot `note_query` records as a query's interfaces).
    fn refresh_link_snapshot(&mut self) {
        self.last_ip_refresh = Instant::now();
        self.local_ips = browse::local_ips();
        self.link_stats = browse::link_stats(self.interfaces.as_ref());
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
        self.address_denials.expire_withheld();
        Self::expire_stale_services(&mut self.services);
        let before = self.services.len();
        self.services
            .retain(|s| s.is_active || now.duration_since(s.last_seen) < grace);
        let services_expired = before - self.services.len();
        self.diagnostics.services_expired_total += services_expired as u64;
        if services_expired > 0 {
            self.touch();
        }
        self.pending_instances
            .retain(|p| now.duration_since(p.last_seen) < grace);
        // Denials live for their NSEC's TTL and only while their service
        // (or pending instance) does: pruned after both were pruned, so a
        // returning instance never inherits a stale denial.
        let owners = self.live_service_keys();
        self.address_denials.retain_owned_by(&owners);
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
            live.insert((entry.name.to_ascii_lowercase(), 12));
            for rec in &entry.answers {
                live.insert((
                    rec.name.trim_end_matches('.').to_ascii_lowercase(),
                    rec.rtype,
                ));
            }
        }
        for svc in &self.services {
            live.insert((svc.service_type.to_ascii_lowercase(), 12));
            let full =
                crate::browse::instance_name(&svc.instance, &svc.service_type).to_ascii_lowercase();
            live.insert((full.clone(), 33));
            live.insert((full, 16));
            if !svc.hostname.is_empty() {
                let host = svc.hostname.trim_end_matches('.').to_ascii_lowercase();
                live.insert((host.clone(), 1));
                live.insert((host, 28));
            }
            for rec in &svc.answers {
                live.insert((
                    rec.name.trim_end_matches('.').to_ascii_lowercase(),
                    rec.rtype,
                ));
            }
        }
        for p in &self.pending_instances {
            live.insert((p.service_type.to_ascii_lowercase(), 12));
            let full =
                crate::browse::instance_name(&p.instance, &p.service_type).to_ascii_lowercase();
            live.insert((full.clone(), 33));
            live.insert((full, 16));
        }
        self.scheduler.evict(live);
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
        // Cursor clamping walks the display list and re-sorts the detail
        // rows; skip it on idle ticks where nothing it reads has changed.
        if self.clamped_gen != Some(self.state_gen) {
            self.clamp_selection();
            self.clamped_gen = Some(self.state_gen);
        }
    }
}

mod denials;
mod diagnostics;
mod findings;
mod ingest;
mod input;
mod layout;
mod questions;
mod rusage;
mod schedule;
mod sightings;
mod state_dump;
mod view;
mod view_state;

#[cfg(test)]
mod tests;
