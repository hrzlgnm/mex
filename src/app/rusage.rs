// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

/// One sample of mex's own resource usage, normalized: memory in KiB,
/// CPU time in whole milliseconds. `None` means "not measurable on
/// this platform" and is never rendered or dumped as zero.
#[derive(Debug, Default, Clone, Copy)]
pub(super) struct ResourceUsage {
    /// CPU time spent executing in user mode.
    pub(super) cpu_user_ms: Option<u64>,
    /// CPU time spent executing in kernel mode.
    pub(super) cpu_sys_ms: Option<u64>,
    /// Peak resident set size (rusage `ru_maxrss`), normalized to KiB.
    pub(super) maxrss_kib: Option<u64>,
    /// Current resident set size, KiB; Linux only.
    pub(super) rss_kib: Option<u64>,
    /// Soft page faults (reclaims).
    pub(super) minflt: Option<u64>,
    /// Hard page faults (disk I/O).
    pub(super) majflt: Option<u64>,
    /// Voluntary context switches.
    pub(super) nvcsw: Option<u64>,
    /// Involuntary context switches.
    pub(super) nivcsw: Option<u64>,
}

/// Overlay rows for the Process section body: the caller adds the
/// header and omits the whole section when nothing is measurable
/// (Windows). Pure over the sample, so tests pin exact rendering.
pub(super) fn rows(u: &ResourceUsage) -> Vec<(String, String)> {
    let mut out = Vec::new();
    if let (Some(user), Some(sys)) = (u.cpu_user_ms, u.cpu_sys_ms) {
        out.push((
            "cpu".to_string(),
            format!("u {} · s {}", fmt_cpu_ms(user), fmt_cpu_ms(sys)),
        ));
    }
    match (u.rss_kib, u.maxrss_kib) {
        (Some(rss), Some(peak)) => out.push((
            "memory".to_string(),
            format!("rss {} · peak {}", fmt_kib(rss), fmt_kib(peak)),
        )),
        (None, Some(peak)) => out.push(("memory".to_string(), format!("peak {}", fmt_kib(peak)))),
        // Current without peak does not occur; neither measured
        // leaves the row to the empty-sample case.
        _ => {}
    }
    if let (Some(minor), Some(major)) = (u.minflt, u.majflt) {
        out.push((
            "page faults".to_string(),
            format!("{minor} minor · {major} major"),
        ));
    }
    if let (Some(vol), Some(invol)) = (u.nvcsw, u.nivcsw) {
        out.push((
            "ctx switches".to_string(),
            format!("{vol} vol · {invol} invol"),
        ));
    }
    out
}

/// State-dump entries for one sample: `(key, value)` into the dump's
/// diagnostics map. A key appears only when its value is measurable on
/// this platform — absence is the "not measured" signal, never zero.
pub(super) fn dump_entries(u: &ResourceUsage) -> Vec<(&'static str, u64)> {
    let mut out = Vec::new();
    for (key, value) in [
        ("cpu_user_ms", u.cpu_user_ms),
        ("cpu_sys_ms", u.cpu_sys_ms),
        ("rss_kib", u.rss_kib),
        ("maxrss_kib", u.maxrss_kib),
        ("minflt", u.minflt),
        ("majflt", u.majflt),
        ("nvcsw", u.nvcsw),
        ("nivcsw", u.nivcsw),
    ] {
        if let Some(value) = value {
            out.push((key, value));
        }
    }
    out
}

/// CPU duration from whole milliseconds: the overlay's duration style
/// (`fmt_age`) with a milliseconds tier underneath, since a fresh
/// session often has sub-second CPU time.
fn fmt_cpu_ms(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms}ms")
    } else {
        fmt_age(ms / 1000)
    }
}

/// Memory size from KiB, in the overlay's byte formatting.
fn fmt_kib(kib: u64) -> String {
    fmt_bytes(kib.saturating_mul(1024))
}

/// rusage `ru_maxrss` normalized to KiB. Linux reports KiB, macOS
/// bytes, so the sampler passes `cfg!(target_os = "macos")` and both
/// paths stay compiled and testable everywhere. Takes the type
/// getrusage reports (`c_long`, i32 on 32-bit release targets) so no
/// call-site conversion is needed.
#[cfg(unix)]
pub(super) fn maxrss_kib(ru_maxrss: nix::libc::c_long, raw_is_bytes: bool) -> u64 {
    let raw = ru_maxrss.max(0) as u64;
    if raw_is_bytes {
        raw / 1024
    } else {
        raw
    }
}

/// Fresh sample of this process's own cost: `getrusage(RUSAGE_SELF)`
/// through nix's safe wrapper on unix, plus the current resident set
/// on Linux. Read on demand by the overlay and the dump, so nothing
/// is stored and the diagnostics never change what they measure; a
/// failed read degrades to the empty (Windows-shaped) sample instead
/// of failing the caller.
#[cfg(unix)]
pub(super) fn sample() -> ResourceUsage {
    use nix::sys::resource::{getrusage, UsageWho};
    use nix::sys::time::TimeValLike;
    match getrusage(UsageWho::RUSAGE_SELF) {
        Ok(u) => ResourceUsage {
            cpu_user_ms: Some(u.user_time().num_milliseconds().max(0) as u64),
            cpu_sys_ms: Some(u.system_time().num_milliseconds().max(0) as u64),
            maxrss_kib: Some(maxrss_kib(u.max_rss(), cfg!(target_os = "macos"))),
            rss_kib: current_rss_kib(),
            minflt: Some(u.minor_page_faults().max(0) as u64),
            majflt: Some(u.major_page_faults().max(0) as u64),
            nvcsw: Some(u.voluntary_context_switches().max(0) as u64),
            nivcsw: Some(u.involuntary_context_switches().max(0) as u64),
        },
        Err(_) => ResourceUsage::default(),
    }
}

/// Windows has no rusage: the empty sample, so both callers omit the
/// Process section and the dump keys (see `rows`).
#[cfg(not(unix))]
pub(super) fn sample() -> ResourceUsage {
    ResourceUsage::default()
}

/// Current resident set on Linux, in KiB, from the `VmRSS:` line of
/// `/proc/self/status` — same kernel accounting as statm, but already
/// in KiB, so no page-size assumption can be wrong on exotic targets.
/// `None` on any read or parse failure.
#[cfg(all(unix, target_os = "linux"))]
fn current_rss_kib() -> Option<u64> {
    let status = std::fs::read_to_string("/proc/self/status").ok()?;
    status
        .lines()
        .find_map(|l| l.strip_prefix("VmRSS:"))
        .and_then(|rest| rest.split_whitespace().next())
        .and_then(|kib| kib.parse::<u64>().ok())
}

/// No procfs off Linux: the peak (from rusage) is all there is.
#[cfg(all(unix, not(target_os = "linux")))]
fn current_rss_kib() -> Option<u64> {
    None
}
