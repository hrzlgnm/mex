use std::collections::BTreeMap;
use std::time::{Instant, SystemTime};

/// Experimental state dump for cross-tool comparison (sibling
/// mdns-tui-browser JSON dumps, `avahi-browse -aprt` text).
///
/// JSON mirrors the sibling `StateDump` shape where mex has an equivalent
/// (metadata/services/serviceTypes/metrics/options/filters/sorting) and
/// carries mex-only detail under `mex*` keys. Everything here is
/// best-effort and unstable.

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Metadata {
    pub dump_timestamp: String,
    pub application_name: String,
    pub version: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MexRecord {
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
#[serde(rename_all = "camelCase")]
pub struct MexQuestion {
    pub name: String,
    pub rtype_str: String,
    pub source: String,
    pub received_at: String,
    pub age_secs: u64,
}

/// Resolved service row: sibling-compatible fields first, mex extras last.
/// Unknown fields are ignored by sibling tooling on load.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpService {
    pub fullname: String,
    pub host: String,
    pub service_type: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub subtype: Option<String>,
    pub addresses: Vec<String>,
    #[serde(default, skip_serializing_if = "is_zero_u16")]
    pub port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub txt_records: Vec<String>,
    pub is_online: bool,
    pub is_flapping: bool,
    pub created_at: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub updated_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_online_at: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_offline_at: Option<String>,
    pub session_history: Vec<DumpSession>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub subtypes: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mex_records: Vec<MexRecord>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mex_questions: Vec<MexQuestion>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpSession {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub start_time: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub end_time: Option<String>,
}

/// Unresolved group (enumeration row, pending instance): raw rows only.
#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct MexRawGroup {
    pub name: String,
    pub records: Vec<MexRecord>,
    pub questions: Vec<MexQuestion>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpOptions {
    pub passive: bool,
    pub service_types: Vec<String>,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpFilters {
    pub query: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DumpSorting {
    pub field: String,
    pub direction: String,
}

#[derive(serde::Serialize)]
#[serde(rename_all = "camelCase")]
pub struct StateDump {
    pub metadata: Metadata,
    pub services: Vec<DumpService>,
    pub service_types: Vec<String>,
    pub metrics: BTreeMap<String, u64>,
    pub options: DumpOptions,
    pub filters: DumpFilters,
    pub sorting: DumpSorting,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mex_enum: Vec<MexRawGroup>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub mex_pending: Vec<MexRawGroup>,
}

fn is_zero_u16(v: &u16) -> bool {
    *v == 0
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

/// File stem matching the sibling (`20260207T120102.089898`).
pub fn file_stem_iso() -> String {
    let now: chrono::DateTime<chrono::Utc> = SystemTime::now().into();
    now.format("%Y%m%dT%H%M%S%.6f").to_string()
}

/// Minimal avahi field escaping for the experimental sidecar: backslash
/// and the `;` separator. Sibling avahi escapes more (decimal `\DDD`,
/// `\.`); diff scripts should normalize rather than byte-compare.
pub fn escape_avahi_field(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            ';' => out.push_str("\\;"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

fn escape_avahi_txt(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            _ => out.push(c),
        }
    }
    out
}

/// One `=;iface;proto;instance;type;local;host;addr;port[;txt...]` line per
/// address, mirroring `avahi-browse -aprt` resolved rows. `txt_records`
/// are space-separated double-quoted strings after the port.
#[allow(clippy::too_many_arguments)]
pub fn avahi_line(
    iface: &str,
    proto: &str,
    instance: &str,
    service_type: &str,
    host: &str,
    addr: &str,
    port: u16,
    txt_records: &[String],
) -> String {
    let iface = if iface.is_empty() { "unknown" } else { iface };
    let mut line = format!(
        "=;{};{};{};{};local;{};{};{}",
        escape_avahi_field(iface),
        proto,
        escape_avahi_field(instance),
        escape_avahi_field(service_type),
        escape_avahi_field(host.trim_end_matches('.')),
        escape_avahi_field(addr),
        port,
    );
    if !txt_records.is_empty() {
        let txt = txt_records
            .iter()
            .map(|t| format!("\"{}\"", escape_avahi_txt(t)))
            .collect::<Vec<_>>()
            .join(" ");
        line.push(';');
        line.push_str(&txt);
    }
    line
}

pub fn proto_for_addr(addr: &str) -> &'static str {
    match addr.parse::<std::net::IpAddr>() {
        Ok(ip) if ip.is_ipv4() => "IPv4",
        Ok(_) => "IPv6",
        Err(_) => "IPv4",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn avahi_line_matches_resolved_shape() {
        let line = avahi_line(
            "wlp13s0",
            "IPv4",
            "Test",
            "_http._tcp.local",
            "test.local.",
            "192.168.1.10",
            80,
            &["path=/api".to_string()],
        );
        assert_eq!(
            line,
            "=;wlp13s0;IPv4;Test;_http._tcp.local;local;test.local;192.168.1.10;80;\"path=/api\""
        );
    }

    #[test]
    fn avahi_line_escapes_separator() {
        let line = avahi_line(
            "if",
            "IPv4",
            "a;b\\c",
            "_http._tcp.local",
            "h",
            "1.2.3.4",
            80,
            &[],
        );
        assert!(line.contains("a\\;b\\\\c"), "got: {line}");
    }

    #[test]
    fn avahi_line_omits_txt_when_empty() {
        let line = avahi_line("if", "IPv6", "n", "_t._tcp.local", "h", "::1", 1, &[]);
        assert!(!line.ends_with(';'), "got: {line}");
        assert_eq!(line.matches(';').count(), 8);
    }

    #[test]
    fn instant_to_iso_is_parseable() {
        let s = instant_to_iso(Instant::now());
        assert!(s.ends_with('Z'), "got: {s}");
        assert!(chrono::DateTime::parse_from_rfc3339(&s).is_ok(), "got: {s}");
    }

    #[test]
    fn dump_service_skips_empty_port_and_txt() {
        let svc = DumpService {
            fullname: "T._http._tcp.local.".into(),
            host: "h.local.".into(),
            service_type: "_http._tcp.local.".into(),
            subtype: None,
            addresses: vec![],
            port: 0,
            txt_records: vec![],
            is_online: true,
            is_flapping: false,
            created_at: dump_timestamp_iso(),
            updated_at: None,
            last_online_at: None,
            last_offline_at: None,
            session_history: vec![],
            subtypes: vec![],
            mex_records: vec![],
            mex_questions: vec![],
        };
        let v = serde_json::to_value(&svc).unwrap();
        assert!(v.get("port").is_none(), "port 0 must skip, got: {v}");
        assert!(
            v.get("txtRecords").is_none(),
            "empty txt must skip, got: {v}"
        );
        assert!(v.get("subtype").is_none(), "got: {v}");
    }
}
