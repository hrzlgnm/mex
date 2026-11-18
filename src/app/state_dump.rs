use super::*;

impl App {
    /// Live TXT pairs, deduped and sorted by key (expired and goodbye
    /// rows omitted). High-entropy values are redacted (keys kept) so
    /// dumps are safe to share; dedup runs after redaction so identical
    /// keys collapse to one `key=*REDACTED*` row.
    pub(super) fn txt_records_for_dump(svc: &ServiceEntry) -> Vec<String> {
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

    pub(super) fn dump_answer_row(rec: &browse::RawRecord, book: &AddressBook) -> dump::DumpAnswer {
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

    pub(super) fn dump_question_row(q: &QuestionRow, book: &AddressBook) -> dump::DumpQuestion {
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

    pub(super) fn dump_service(&self, svc: &ServiceEntry, book: &AddressBook) -> dump::DumpService {
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
            address_denials: self
                .address_denials
                .dump(&service_key(&svc.instance, &svc.service_type)),
        }
    }

    /// Snapshot of mex's own browse state.
    pub(super) fn state_dump(&self) -> dump::StateDump {
        let book = self.address_book();
        let mut service_types: Vec<String> = self.scheduler.known_types().iter().cloned().collect();
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
        metrics.insert(
            "enum_known".to_string(),
            self.scheduler.enum_known().len() as u64,
        );
        metrics.insert(
            "continuous_interests".to_string(),
            self.scheduler.continuous().len() as u64,
        );
        metrics.insert(
            "requery_pending".to_string(),
            self.scheduler.requeries().len() as u64,
        );
        metrics.insert(
            "uptime_secs".to_string(),
            self.start_time.elapsed().as_secs(),
        );
        let now = Instant::now();
        let mut interest_keys: HashSet<(String, u16)> =
            self.scheduler.query_history().keys().cloned().collect();
        for key in self.scheduler.requeries().keys() {
            interest_keys.insert(Self::provenance_key(&key.0, key.1));
        }
        for key in self.scheduler.continuous().keys() {
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

    pub(super) fn save_state_dump(&self) -> Result<String> {
        let json_path = self.save_state_dump_to(std::path::Path::new(""))?;
        Ok(json_path.to_string_lossy().into_owned())
    }

    pub(super) fn save_state_dump_to(&self, dir: &std::path::Path) -> Result<std::path::PathBuf> {
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
}
