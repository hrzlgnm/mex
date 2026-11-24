// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    /// File a question asking for a service, so the Records view can show
    /// who is asking (and the hex pane can show the query packet).
    /// Enumeration questions file on their selectable enumeration row.
    pub(super) fn route_question(&mut self, q: &browse::RawRecord, ev: &browse::Event) {
        self.scheduler.note_observed(q, ev.source);
        let name = q.name.trim_end_matches('.').to_ascii_lowercase();
        if is_enum_name(&name) {
            for entry in &mut self.enum_entries {
                if entry.name.to_ascii_lowercase() == name {
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
            .to_ascii_lowercase();
            let host = self.services[i]
                .hostname
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if full == name
                || host == name
                || self.services[i].service_type.to_ascii_lowercase() == name
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

    /// File one question row (see `file_question_row`) and count an
    /// evicted row in `drops`, for the dump truncation marker.
    pub(super) fn file_question_counted(
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

    /// File one question row, refreshing the timestamp when the same
    /// (name, type, source) asks again. Caps the list at `QUESTION_CAP`
    /// rows (the window ages rows out separately, in `evict_expired`).
    /// Returns true when an old row was evicted, so callers can count
    /// drops for the dump truncation marker.
    ///
    /// Prefer `file_question_counted` at call sites: it files the row
    /// and bumps the entry's eviction counter in one call.
    pub(super) fn file_question_row(
        rows: &mut Vec<QuestionRow>,
        name: String,
        rtype_str: String,
        source: std::net::SocketAddr,
        at: Instant,
        bytes: Vec<u8>,
    ) -> bool {
        // DNS names compare case-insensitively (RFC 4343); the row keeps
        // the latest asking's case for display.
        let key = name.to_ascii_lowercase();
        match rows.iter().position(|(n, t, src, _, _)| {
            n.to_ascii_lowercase() == key && t == &rtype_str && src == &source
        }) {
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
    pub(super) fn route_own_question(&mut self, name: &str, rtype: u16, qu: bool) {
        // Display in the same fully-qualified form as observed questions
        // (`display_name` adds the root dot); match on the dot-less key.
        let bare = name.trim_end_matches('.');
        let display = format!("{bare}.");
        let key = bare.to_ascii_lowercase();
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
                if entry.name.to_ascii_lowercase() == key {
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
            .to_ascii_lowercase();
            let host = self.services[i]
                .hostname
                .trim_end_matches('.')
                .to_ascii_lowercase();
            if full == key
                || host == key
                || self.services[i].service_type.to_ascii_lowercase() == key
            {
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
            let full = format!("{}.{}", p.instance, p.service_type).to_ascii_lowercase();
            if full == key || p.service_type.to_ascii_lowercase() == key {
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
}
