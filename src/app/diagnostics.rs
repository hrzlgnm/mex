// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// Cumulative per-packet accounting for the diagnostics overlay.
    pub(super) fn note_packet_diagnostics(&mut self, ev: &browse::Event) {
        let now = Instant::now();
        let diag = &mut self.diagnostics;
        diag.bytes_total += ev.raw_bytes.len() as u64;
        diag.packet_times.push_back(now);
        diag.last_packet_at = Some(now);
        diag.records_total += ev.answers.len() as u64;
        for rec in &ev.answers {
            *diag.records_by_type.entry(rec.rtype).or_insert(0) += 1;
            if rec.flush_bit {
                diag.flush_seen += 1;
            }
            if rec.ttl == 0 {
                diag.goodbyes_seen += 1;
            }
        }
        diag.questions_total += ev.questions.len() as u64;
        for q in &ev.questions {
            if q.qu {
                diag.qu_questions_seen += 1;
            } else {
                diag.qm_questions_seen += 1;
            }
        }
        diag.kas_seen += ev.query_kas.len() as u64;
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
        *diag
            .iface_rx
            .entry(Self::link_key(iface, ifindex))
            .or_insert(0) += 1;
        diag.count_source(ev.source);
    }

    /// Rows for the diagnostics overlay: `(key, value)` with an empty value
    /// marking a section header. Pure snapshot of cumulative counters plus
    /// live state; cheap enough to rebuild every frame.
    #[cfg(test)]
    pub fn diagnostics_rows(&self) -> Vec<(String, String)> {
        self.diagnostics_rows_in(&self.anomalies())
    }

    /// `diagnostics_rows` over a precomputed finding set (see
    /// `anomaly_counts_in`), so the overlay shares the frame's analyzer run.
    pub fn diagnostics_rows_in(&self, found: &[anomalies::Anomaly]) -> Vec<(String, String)> {
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
            .diagnostics
            .packet_times
            .iter()
            .filter(|t| t.elapsed() <= Duration::from_secs(60))
            .count();
        kv(&mut rows, "pkt/min last 60s", last_60.to_string());
        let avg = self
            .diagnostics
            .bytes_total
            .checked_div(self.packet_count)
            .unwrap_or(0);
        kv(
            &mut rows,
            "bytes",
            format!(
                "{} (avg {avg} B/pkt)",
                fmt_bytes(self.diagnostics.bytes_total)
            ),
        );
        kv(
            &mut rows,
            "last packet",
            self.diagnostics
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
                self.diagnostics.sightings_dropped
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
                self.diagnostics.services_seen_total, self.diagnostics.services_expired_total
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
            format!(
                "{} / {}",
                self.scheduler.known_types().len(),
                self.scheduler.enum_known().len()
            ),
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
                self.diagnostics.records_total,
                self.diagnostics
                    .records_by_type
                    .get(&12)
                    .copied()
                    .unwrap_or(0),
                self.diagnostics
                    .records_by_type
                    .get(&33)
                    .copied()
                    .unwrap_or(0),
                self.diagnostics
                    .records_by_type
                    .get(&16)
                    .copied()
                    .unwrap_or(0),
                self.diagnostics
                    .records_by_type
                    .get(&1)
                    .copied()
                    .unwrap_or(0),
                self.diagnostics
                    .records_by_type
                    .get(&28)
                    .copied()
                    .unwrap_or(0),
                self.other_records_total(),
            ),
        );
        let flush_pct = if self.diagnostics.records_total > 0 {
            self.diagnostics.flush_seen as f64 * 100.0 / self.diagnostics.records_total as f64
        } else {
            0.0
        };
        kv(
            &mut rows,
            "flush-bit / goodbyes",
            format!(
                "{:.0}% flush · {} goodbyes",
                flush_pct, self.diagnostics.goodbyes_seen
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
                self.diagnostics.questions_total,
                self.diagnostics.qu_questions_seen,
                self.diagnostics.qm_questions_seen,
                self.diagnostics.kas_seen,
            ),
        );

        // Query engine.
        section(&mut rows, "Queries");
        let sent = self.diagnostics.q_sent_continuous + self.diagnostics.q_sent_refresh;
        let supp = self.diagnostics.suppressed_continuous + self.diagnostics.suppressed_refresh;
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
                self.diagnostics.q_sent_continuous,
                self.diagnostics.q_sent_refresh,
                self.diagnostics.qu_sent
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
                self.diagnostics.ka_sent,
                if sent > 0 {
                    self.diagnostics.ka_sent as f64 / sent as f64
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
                self.scheduler.continuous().len(),
                self.next_continuous_in(),
                self.interval_histogram()
            ),
        );
        kv(
            &mut rows,
            "requeries",
            format!(
                "{} pending · {} overdue · {}",
                self.scheduler.requeries().len(),
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
        let mut iface_rows: Vec<(&String, &u64)> = self.diagnostics.iface_rx.iter().collect();
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
            self.diagnostics.source_rx.iter().collect();
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

    pub(super) fn current_record_liveness(&self) -> (usize, usize, usize) {
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

    pub(super) fn other_records_total(&self) -> u64 {
        self.diagnostics
            .records_by_type
            .iter()
            .filter(|(t, _)| !matches!(**t, 12 | 33 | 16 | 1 | 28))
            .map(|(_, c)| *c)
            .sum()
    }

    pub(super) fn next_continuous_in(&self) -> String {
        let now = Instant::now();
        self.scheduler
            .continuous()
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

    pub(super) fn interval_histogram(&self) -> String {
        if self.scheduler.continuous().is_empty() {
            return "no interests".to_string();
        }
        let mut buckets: HashMap<String, usize> = HashMap::new();
        for e in self.scheduler.continuous().values() {
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

    pub(super) fn requery_overdue(&self) -> usize {
        let now = Instant::now();
        self.scheduler
            .requeries()
            .values()
            .filter(|(due, _)| now >= *due)
            .count()
    }

    pub(super) fn suppressions_last_60s(&self) -> usize {
        self.diagnostics
            .suppressed_times
            .iter()
            .filter(|t| t.elapsed() <= Duration::from_secs(60))
            .count()
    }

    /// RFC 6762 §11 refusal counter: unicast-destination packets from
    /// off-link sources, silently discarded by the listeners.
    pub(super) fn offlink_row(&self) -> String {
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
    pub(super) fn malformed_row(&self) -> String {
        let total = self.drop_stats.malformed_total();
        match self.drop_stats.malformed_last() {
            Some((src, at)) => format!(
                "{total} total · last {src} {} ago",
                fmt_age(at.elapsed().as_secs())
            ),
            None => format!("{total} total"),
        }
    }

    pub(super) fn unanswered_histogram(&self) -> String {
        if self.scheduler.requeries().is_empty() {
            return "none unanswered".to_string();
        }
        let mut counts = [0usize; 4];
        for (_, c) in self.scheduler.requeries().values() {
            let idx = usize::from((*c).min(4).saturating_sub(1).min(3));
            counts[idx] += 1;
        }
        format!(
            "miss×1:{} ×2:{} ×3:{} ×4:{}",
            counts[0], counts[1], counts[2], counts[3]
        )
    }
}
