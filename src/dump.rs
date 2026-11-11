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
    pub iface: String,
    pub ifindex: u32,
    pub flush: bool,
    pub received_at: String,
    pub age_secs: u64,
}

#[derive(serde::Serialize)]
pub struct DumpQuestion {
    pub name: String,
    pub rtype_str: String,
    pub source: String,
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
}

/// Unresolved group: enumeration row or pending instance.
#[derive(serde::Serialize)]
pub struct RawGroup {
    pub name: String,
    pub answers: Vec<DumpAnswer>,
    pub questions: Vec<DumpQuestion>,
}

#[derive(serde::Serialize)]
pub struct StateDump {
    pub metadata: Metadata,
    pub passive: bool,
    pub services: Vec<DumpService>,
    /// Live browse set, as stored (lowercase, dotless).
    pub service_types: Vec<String>,
    pub metrics: BTreeMap<String, u64>,
    pub enum_groups: Vec<RawGroup>,
    pub pending: Vec<RawGroup>,
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
/// reachable host. LAN URLs (RFC 1918, link-local, `.local`, home-router
/// names) stay visible since they are the debugging payload.
pub fn is_public_url(v: &str) -> bool {
    let Some(pos) = v.find("://") else {
        return false;
    };
    let authority = v[pos + 3..].split('/').next().unwrap_or("");
    let hostport = authority.rsplit('@').next().unwrap_or("");
    let host = if let Some(rest) = hostport.strip_prefix('[') {
        rest.split(']').next().unwrap_or("")
    } else {
        hostport.split(':').next().unwrap_or("")
    };
    is_public_host(host)
}
/// Redact a `key=value` pair as `key=*REDACTED*` when the value is a
/// high-entropy token or a publicly reachable URL, keeping the key so
/// dumps stay comparable. Pairs without `=` or with ordinary values
/// pass through.
pub fn redact_txt_value(pair: &str) -> String {
    match pair.split_once('=') {
        Some((k, v)) if is_high_entropy_value(v) || is_public_url(v) => {
            format!("{k}=*REDACTED*")
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
}
