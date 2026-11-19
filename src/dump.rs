// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use std::collections::{BTreeMap, HashMap};
use std::time::{Instant, SystemTime};

/// Experimental dump of mex's own browse state. Field names follow the
/// Rust model (snake_case); derived convenience fields are marked as such.

#[derive(serde::Serialize)]
pub struct Metadata {
    pub dump_timestamp: String,
    pub application_name: String,
    pub version: String,
}

#[derive(serde::Serialize)]
pub struct DumpAnswer {
    pub name: String,
    pub rtype: u16,
    pub rtype_str: String,
    pub ttl: u32,
    pub ttl_remaining: u32,
    pub rdata: String,
    pub source: String,
    /// Device names the source address resolves to (#246), preferred
    /// first; omitted when nothing announced names it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_names: Vec<String>,
    /// The name was matched by IPv6 interface ID, not exactly.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub source_name_inferred: bool,
    pub iface: String,
    pub ifindex: u32,
    pub flush: bool,
    pub section: String,
    pub multicast_dst: bool,
    pub received_at: String,
    pub age_secs: u64,
}

#[derive(serde::Serialize)]
pub struct DumpQuestion {
    pub name: String,
    pub rtype_str: String,
    pub source: String,
    /// Device names the source address resolves to (#246), preferred
    /// first; omitted when nothing announced names it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_names: Vec<String>,
    /// The name was matched by IPv6 interface ID, not exactly.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub source_name_inferred: bool,
    pub received_at: String,
    pub age_secs: u64,
}

/// One confirmed service, as mex tracks it.
#[derive(serde::Serialize)]
pub struct DumpService {
    pub instance: String,
    pub service_type: String,
    pub hostname: String,
    pub port: u16,
    pub subtypes: Vec<String>,
    pub addresses: Vec<String>,
    /// Live TXT pairs, derived from the TXT records below.
    pub txt_records: Vec<String>,
    pub is_active: bool,
    pub last_seen_age_secs: u64,
    pub answers: Vec<DumpAnswer>,
    pub questions: Vec<DumpQuestion>,
    /// The questions list is capped; when rows were evicted, this marks
    /// the list as incomplete and counts the dropped rows so consumers
    /// do not mistake it for a complete packet log.
    pub questions_truncated: bool,
    pub questions_dropped: u64,
    /// Address types this service's own responder denies via NSEC; their
    /// rows are absent from `answers` (#245).
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub address_denials: Vec<DumpDenial>,
}

/// One live NSEC address denial of a service.
#[derive(serde::Serialize)]
pub struct DumpDenial {
    pub rtype_str: String,
    /// `rfc` (hostname-owned NSEC with the SRV) or `legacy` (instance-owned
    /// NSEC listing the missing types).
    pub form: String,
    /// Host the denial applies to (RFC form); absent for every host.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host: Option<String>,
    pub source: String,
    pub ttl_remaining_secs: u64,
}

/// Unresolved group: enumeration row or pending instance.
#[derive(serde::Serialize)]
pub struct RawGroup {
    pub name: String,
    pub answers: Vec<DumpAnswer>,
    pub questions: Vec<DumpQuestion>,
    pub questions_truncated: bool,
    pub questions_dropped: u64,
}

/// Authoritative per-interest query state: the latest query event,
/// refresh attempt count, next deadline, owning timer, and lifecycle
/// status. Rows here survive Questions-pane caps; the pane shows
/// transient observations, this section shows the schedule truth.
#[derive(serde::Serialize)]
pub struct DumpInterest {
    pub name: String,
    pub rtype: u16,
    pub rtype_str: String,
    /// Owning schedule: `refresh`, `browse`, or `expired`.
    pub timer: String,
    /// Lifecycle: `transmitted`, `suppressed`, `answered`, or `abandoned`.
    pub status: String,
    /// Unanswered refresh count (0 when no refresh is pending).
    pub attempt: u8,
    pub next_due_in_secs: Option<u64>,
    /// Kind of the latest query event, if any.
    pub last_origin: Option<String>,
    pub last_event_age_secs: Option<u64>,
    /// Per-origin ages: the latest event alone cannot distinguish a
    /// transmitted refresh later re-asked by a neighbor from the
    /// reverse order once the schedule clears.
    pub last_transmitted_age_secs: Option<u64>,
    pub last_suppressed_age_secs: Option<u64>,
    pub last_observed_age_secs: Option<u64>,
    /// Querier and ingress link of the latest observed remote question,
    /// if any — the only provenance event with a network source.
    pub last_observed_from: Option<String>,
    pub last_observed_iface: Option<String>,
}

/// One responder group of a `conflicting-answers` finding (#247).
#[derive(serde::Serialize)]
pub struct DumpResponder {
    pub sources: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    pub addresses: Vec<String>,
}

#[derive(serde::Serialize)]
pub struct DumpAnomaly {
    pub kind: String,
    pub severity: String,
    pub service: String,
    /// Further services the same question finding filed on (one observed
    /// question routes to every service whose name it asks for). Listed
    /// once in the dump; omitted when the finding has a single service.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub also_services: Vec<String>,
    pub record_name: Option<String>,
    pub rtype: Option<u16>,
    pub rtype_str: Option<String>,
    pub rdata: Option<String>,
    pub source: Option<String>,
    /// Responder groups and their sorted address sets, for
    /// `conflicting-answers`; omitted for other kinds.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub responders: Vec<DumpResponder>,
    /// Device names the source address resolves to (#246), preferred
    /// first; omitted when nothing announced names it.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub source_names: Vec<String>,
    /// The name was matched by IPv6 interface ID, not exactly.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub source_name_inferred: bool,
    pub message: String,
    pub rfc: String,
    pub requirement: String,
    /// DNS section that carried the flagged record (`answer`,
    /// `authority`, `additional`, `known-answer`), for findings whose
    /// verdict depends on it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub section: Option<String>,
    /// The question the flagged response most likely answered
    /// (`name TYPE`), when one was seen shortly before it.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_response_to: Option<String>,
    /// Whether this mex instance sent that question, so findings it
    /// caused itself can be filtered out.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_response_to_own: Option<bool>,
}

#[derive(serde::Serialize)]
pub struct StateDump {
    pub metadata: Metadata,
    pub passive: bool,
    pub services: Vec<DumpService>,
    /// Live browse set, as stored (lowercase, dotless).
    pub service_types: Vec<String>,
    pub diagnostics: BTreeMap<String, u64>,
    pub enum_groups: Vec<RawGroup>,
    pub pending: Vec<RawGroup>,
    /// Authoritative per-interest query state (uncapped).
    pub interests: Vec<DumpInterest>,
    /// How long a question row stays listed after its querier last
    /// asked (#238): the time span every `questions` list covers.
    /// `questions_truncated` means only the safety cap dropped rows.
    pub question_window_secs: u64,
    pub anomalies: Vec<DumpAnomaly>,
}

/// Wall-clock ISO8601 (`%Y-%m-%dT%H:%M:%S%.6fZ`) for an `Instant` by
/// subtracting its elapsed time from now. Falls back to now on underflow.
pub fn instant_to_iso(at: Instant) -> String {
    let st = SystemTime::now()
        .checked_sub(at.elapsed())
        .unwrap_or_else(SystemTime::now);
    system_time_to_iso(st)
}

pub fn system_time_to_iso(st: SystemTime) -> String {
    let dt: chrono::DateTime<chrono::Utc> = st.into();
    dt.format("%Y-%m-%dT%H:%M:%S%.6fZ").to_string()
}

pub fn dump_timestamp_iso() -> String {
    system_time_to_iso(SystemTime::now())
}

/// Shannon entropy in bits per character.
fn shannon_entropy(s: &str) -> f64 {
    let mut counts = HashMap::new();
    let mut n = 0u64;
    for c in s.chars() {
        *counts.entry(c).or_insert(0u64) += 1;
        n += 1;
    }
    if n == 0 {
        return 0.0;
    }
    counts
        .values()
        .map(|&c| {
            let p = c as f64 / n as f64;
            -p * p.log2()
        })
        .sum()
}

/// Whether a TXT value looks like a token/key/hash: long, single-token
/// charset (hex/base64/UUID-style, no spaces), and dense. Short values
/// and human-readable text (URLs, names, phrases) never match. The 3.2
/// floor also catches repetitive hex device IDs, which carry less
/// entropy but are fingerprints all the same.
pub fn is_high_entropy_value(v: &str) -> bool {
    v.len() >= 20
        && v.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '+' | '/' | '=' | '_' | '-' | '.'))
        && shannon_entropy(v) >= 3.2
}

/// Whether an IP literal is publicly routable (i.e. not private,
/// loopback, link-local, unique-local, or multicast).
fn is_public_ip(ip: &std::net::IpAddr) -> bool {
    match ip {
        std::net::IpAddr::V4(v) => {
            let o = v.octets();
            !(o[0] == 10
                || (o[0] == 172 && (16..32).contains(&o[1]))
                || (o[0] == 192 && o[1] == 168)
                || o[0] == 127
                || (o[0] == 169 && o[1] == 254)
                || o[0] == 0
                || o[0] >= 224)
        }
        std::net::IpAddr::V6(v) => {
            let s = v.segments();
            !(v.is_loopback()
                || v.is_unspecified()
                || (s[0] & 0xffc0) == 0xfe80
                || (s[0] & 0xfe00) == 0xfc00
                || (s[0] & 0xff00) == 0xff00)
        }
    }
}

/// Whether a URL host is publicly reachable. Single-label names and
/// home-network suffixes (mDNS, homenet, router pseudo-TLDs) count as
/// private; anything else (e.g. a DynDNS hostname) counts as public.
fn is_public_host(host: &str) -> bool {
    let h = host.trim_end_matches('.').to_ascii_lowercase();
    if h.is_empty() {
        return false;
    }
    if let Ok(ip) = h.parse::<std::net::IpAddr>() {
        return is_public_ip(&ip);
    }
    if !h.contains('.') {
        return false;
    }
    for suf in [
        ".local",
        ".localhost",
        ".invalid",
        ".internal",
        ".lan",
        ".home",
        ".home.arpa",
        ".box",
        ".repeater",
    ] {
        if h.ends_with(suf) {
            return false;
        }
    }
    true
}

/// Whether a TXT value is a URL (`scheme://...`) pointing at a publicly
/// reachable host. Parsing follows the WHATWG URL standard via the `url`
/// crate (userinfo, ports, bracketed IPv6 handled there); the
/// public/private verdict stays local policy below. LAN URLs (RFC 1918,
/// link-local, `.local`, home-router names) stay visible since they are
/// the debugging payload.
pub fn is_public_url(v: &str) -> bool {
    let Ok(url) = url::Url::parse(v) else {
        return false;
    };
    let Some(host) = url.host_str() else {
        return false;
    };
    is_public_host(host)
}
/// Whether a string is a public IPv6 literal. Global unicast device
/// addresses are stable fingerprints; link-local, unique-local,
/// loopback and multicast stay visible.
fn is_public_ip_literal(v: &str) -> bool {
    match v.trim().parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) => is_public_ip(&std::net::IpAddr::V6(ip)),
        _ => false,
    }
}

/// Redact a bare public IPv6 literal, keeping the first and last
/// hextet (`2003:*REDACTED*:7927`) so prefix and host tail stay useful
/// for debugging. Anything else (including IPv4 and non-public IPv6)
/// passes through.
/// Mask every public IPv6 literal among the words of `text`
/// (`redact_ip_literal` per word, ignoring a trailing `,` or `;`), leaving
/// everything else as is. Word-wise, so an address that prefixes another
/// never rewrites part of the longer one.
pub fn redact_ip_words(text: &str) -> String {
    text.split(' ')
        .map(|word| {
            let addr = word.trim_end_matches([',', ';']);
            let tail = &word[addr.len()..];
            if addr.parse::<std::net::IpAddr>().is_ok() {
                format!("{}{tail}", redact_ip_literal(addr))
            } else {
                word.to_string()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub fn redact_ip_literal(rdata: &str) -> String {
    let trimmed = rdata.trim().split('%').next().unwrap_or("");
    match trimmed.parse::<std::net::IpAddr>() {
        Ok(std::net::IpAddr::V6(ip)) if is_public_ip(&std::net::IpAddr::V6(ip)) => {
            let s = ip.segments();
            format!("{:x}:*REDACTED*:{:x}", s[0], s[7])
        }
        _ => rdata.to_string(),
    }
}

/// Redact a `key=value` pair, keeping the key so dumps stay comparable:
/// high-entropy tokens and publicly reachable URLs become `key=*REDACTED*`,
/// public IPv6 literals keep their first and last hextet
/// (`key=2003:*REDACTED*:7927`). Pairs without `=` or with ordinary
/// values pass through.
pub fn redact_txt_value(pair: &str) -> String {
    match pair.split_once('=') {
        Some((k, v)) if is_high_entropy_value(v) || is_public_url(v) => {
            format!("{k}=*REDACTED*")
        }
        Some((k, v)) if is_public_ip_literal(v) => {
            format!("{k}={}", redact_ip_literal(v))
        }
        _ => pair.to_string(),
    }
}

/// Redact an `"; "`-joined TXT rdata string pair-wise.
pub fn redact_txt_rdata(rdata: &str) -> String {
    rdata
        .split("; ")
        .map(redact_txt_value)
        .collect::<Vec<_>>()
        .join("; ")
}

/// File stem (`20260207T120102.089898`).
pub fn file_stem_iso() -> String {
    let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
    now.format("%Y%m%dT%H%M%S%.6f").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn instant_to_iso_is_parseable() {
        let s = instant_to_iso(Instant::now());
        assert!(s.ends_with('Z'), "got: {s}");
        assert!(chrono::DateTime::parse_from_rfc3339(&s).is_ok(), "got: {s}");
    }

    #[test]
    fn redaction_keeps_keys_and_ordinary_values() {
        // Real device fingerprints are redacted, keys kept.
        assert_eq!(
            redact_txt_value("id=328FEBD442638273B38340E9AFE1E9CB"),
            "id=*REDACTED*"
        );
        // Repetitive hex still counts: low entropy, but a fingerprint.
        assert_eq!(
            redact_txt_value("id=8CED8754FF25F0C2D5A6E25CCD5E8A5F"),
            "id=*REDACTED*"
        );
        assert_eq!(
            redact_txt_value("pk=23d94723d5f4df84cfa99ae4e131ec1d6fe081864b7456de66a09ab037021af8"),
            "pk=*REDACTED*"
        );
        assert_eq!(
            redact_txt_value("gid=01518384-aa7a-4445-b1f2-1b0438a16d5a"),
            "gid=*REDACTED*"
        );
        // Short values, human text, URLs, and keyless pairs pass through.
        assert_eq!(redact_txt_value("fn=Schreibtisch"), "fn=Schreibtisch");
        assert_eq!(redact_txt_value("rm="), "rm=");
        assert_eq!(redact_txt_value("bare-flag"), "bare-flag");
        assert_eq!(
            redact_txt_value("path=http://fritz.box:49000/avmnexusdesc.xml"),
            "path=http://fritz.box:49000/avmnexusdesc.xml"
        );
        assert_eq!(
            redact_txt_rdata("id=328FEBD442638273B38340E9AFE1E9CB; fn=Schreibtisch"),
            "id=*REDACTED*; fn=Schreibtisch"
        );
    }

    #[test]
    fn redaction_redacts_public_urls_keeps_lan_urls() {
        // Public DynDNS hostname: redacted.
        assert_eq!(
            redact_txt_value("external_url=https://ha.knulp.home64.de"),
            "external_url=*REDACTED*"
        );
        assert_eq!(
            redact_txt_value("base_url=https://example.com:443/a?b=c"),
            "base_url=*REDACTED*"
        );
        // LAN literals, link-local, and home-router names stay visible.
        assert_eq!(
            redact_txt_value("internal_url=http://192.168.178.27:8095"),
            "internal_url=http://192.168.178.27:8095"
        );
        assert_eq!(
            redact_txt_value("path=http://fritz.box:49000/avmnexusdesc.xml"),
            "path=http://fritz.box:49000/avmnexusdesc.xml"
        );
        assert_eq!(
            redact_txt_value("x=http://[fe80::1]:8123/"),
            "x=http://[fe80::1]:8123/"
        );
        // Userinfo and odd ports are the parser's problem, not ours.
        assert_eq!(
            redact_txt_value("x=http://user:pass@public.example.com:8080/a"),
            "x=*REDACTED*"
        );
        assert_eq!(
            redact_txt_value("x=rtsp://camera.example.com/stream"),
            "x=*REDACTED*"
        );
        assert_eq!(
            redact_txt_value("path=http://printer.local.:9100/x"),
            "path=http://printer.local.:9100/x"
        );
        // Not a URL at all: untouched.
        assert_eq!(
            redact_txt_value("model=SHIELD Android TV"),
            "model=SHIELD Android TV"
        );
    }

    #[test]
    fn redaction_redacts_public_ipv6_keeps_scope() {
        // Global unicast keeps first and last hextet only.
        assert_eq!(
            redact_txt_value("ipv6=2003:e8:bf10:9500:38e1:a9ff:fe2c:7927"),
            "ipv6=2003:*REDACTED*:7927"
        );
        assert_eq!(
            redact_ip_literal("2003:e8:bf10:9500:38e1:a9ff:fe2c:7927"),
            "2003:*REDACTED*:7927"
        );
        // Link-local, ULA, loopback, and IPv4 stay visible.
        assert_eq!(
            redact_txt_value("ipv6=fe80::38e1:a9ff:fe2c:7927"),
            "ipv6=fe80::38e1:a9ff:fe2c:7927"
        );
        assert_eq!(redact_txt_value("ip6=fd00::1"), "ip6=fd00::1");
        assert_eq!(redact_ip_literal("::1"), "::1");
        assert_eq!(redact_ip_literal("192.168.178.30"), "192.168.178.30");
    }
}
