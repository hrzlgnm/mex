// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;
use crate::app::rusage::{self, ResourceUsage};

#[test]
fn process_rows_render_cpu() {
    let u = ResourceUsage {
        cpu_user_ms: Some(83_000),
        cpu_sys_ms: Some(12_500),
        ..ResourceUsage::default()
    };
    assert_eq!(
        rusage::rows(&u),
        vec![("cpu".to_string(), "u 1m23s · s 12s".to_string())]
    );
}

#[test]
fn process_rows_render_memory_current_peak_and_peak_only() {
    // Linux shape: current and peak.
    let u = ResourceUsage {
        rss_kib: Some(45_123),
        maxrss_kib: Some(46_800),
        ..ResourceUsage::default()
    };
    assert_eq!(
        rusage::rows(&u),
        vec![(
            "memory".to_string(),
            "rss 44.1 MiB · peak 45.7 MiB".to_string()
        )]
    );
    // macOS shape: peak only — no current RSS without a new dependency.
    let u = ResourceUsage {
        maxrss_kib: Some(46_800),
        ..ResourceUsage::default()
    };
    assert_eq!(
        rusage::rows(&u),
        vec![("memory".to_string(), "peak 45.7 MiB".to_string())]
    );
}

#[test]
fn process_rows_render_faults_and_switches() {
    let u = ResourceUsage {
        minflt: Some(1_123),
        majflt: Some(4),
        nvcsw: Some(8_231),
        nivcsw: Some(92),
        ..ResourceUsage::default()
    };
    assert_eq!(
        rusage::rows(&u),
        vec![
            (
                "page faults".to_string(),
                "1123 minor · 4 major".to_string()
            ),
            (
                "ctx switches".to_string(),
                "8231 vol · 92 invol".to_string()
            ),
        ]
    );
}

#[test]
fn process_rows_render_the_whole_section_in_order() {
    let u = ResourceUsage {
        cpu_user_ms: Some(83_000),
        cpu_sys_ms: Some(12_500),
        maxrss_kib: Some(46_800),
        rss_kib: Some(45_123),
        minflt: Some(1_123),
        majflt: Some(4),
        nvcsw: Some(8_231),
        nivcsw: Some(92),
    };
    assert_eq!(
        rusage::rows(&u),
        vec![
            ("cpu".to_string(), "u 1m23s · s 12s".to_string()),
            (
                "memory".to_string(),
                "rss 44.1 MiB · peak 45.7 MiB".to_string()
            ),
            (
                "page faults".to_string(),
                "1123 minor · 4 major".to_string()
            ),
            (
                "ctx switches".to_string(),
                "8231 vol · 92 invol".to_string()
            ),
        ]
    );
}

#[test]
fn nothing_measured_renders_no_rows() {
    // The Windows shape: the caller omits the whole Process section.
    assert!(rusage::rows(&ResourceUsage::default()).is_empty());
}

#[test]
fn cpu_row_renders_sub_second_milliseconds() {
    // A freshly started mex often has sub-second CPU time; a bare
    // seconds tier would collapse that to a meaningless `0s`.
    let u = ResourceUsage {
        cpu_user_ms: Some(250),
        cpu_sys_ms: Some(0),
        ..ResourceUsage::default()
    };
    assert_eq!(
        rusage::rows(&u),
        vec![("cpu".to_string(), "u 250ms · s 0ms".to_string())]
    );
}

/// Both unit paths stay compiled so the bytes path is covered on
/// Linux CI, not only on macOS.
#[cfg(unix)]
#[test]
fn maxrss_normalizes_linux_kib_and_macos_bytes_to_kib() {
    // Linux: rusage already reports KiB.
    assert_eq!(rusage::maxrss_kib(46_800, false), 46_800);
    // macOS: rusage reports bytes (its getrusage(2)).
    assert_eq!(rusage::maxrss_kib(47_923_200, true), 46_800);
    // A negative kernel value clamps to zero instead of wrapping.
    assert_eq!(rusage::maxrss_kib(-5, false), 0);
}

#[test]
fn dump_entries_list_only_measured_keys() {
    let u = ResourceUsage {
        cpu_user_ms: Some(1_500),
        maxrss_kib: Some(2_048),
        ..ResourceUsage::default()
    };
    assert_eq!(
        rusage::dump_entries(&u),
        vec![("cpu_user_ms", 1_500), ("maxrss_kib", 2_048)]
    );
    // Absence is the "not measured" signal, never zero.
    assert!(rusage::dump_entries(&ResourceUsage::default()).is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn sample_reads_the_live_process() {
    let a = rusage::sample();
    let b = rusage::sample();
    // Linux measures everything the Process section shows.
    assert!(a.cpu_user_ms.is_some());
    assert!(a.cpu_sys_ms.is_some());
    assert!(a.rss_kib.is_some());
    assert!(a.maxrss_kib.is_some());
    assert!(a.minflt.is_some());
    assert!(a.majflt.is_some());
    assert!(a.nvcsw.is_some());
    assert!(a.nivcsw.is_some());
    assert!(a.rss_kib.unwrap() > 0, "current rss is measured");
    assert!(a.maxrss_kib.unwrap() > 0, "peak rss is measured");
    assert!(
        b.cpu_user_ms.unwrap() >= a.cpu_user_ms.unwrap(),
        "cpu time is non-decreasing"
    );
}

/// Through the existing dump seam: the counters sit next to the
/// traffic metrics, keys present only where measured.
#[cfg(unix)]
#[test]
fn state_dump_carries_process_counters() {
    let app = App::new().unwrap();
    let dump = app.state_dump();
    for key in [
        "cpu_user_ms",
        "cpu_sys_ms",
        "maxrss_kib",
        "minflt",
        "majflt",
        "nvcsw",
        "nivcsw",
    ] {
        assert!(dump.diagnostics.contains_key(key), "missing dump key {key}");
    }
    // Linux also reports the current resident set.
    #[cfg(target_os = "linux")]
    assert!(dump.diagnostics.contains_key("rss_kib"));
}
