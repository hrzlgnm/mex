// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use super::*;

impl App {
    pub(super) fn toggle_collapse(&mut self) {
        let items = self.display_items();
        match items.get(self.view_state.selected_display) {
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
    pub(super) fn toggle_collapse_all(&mut self) {
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
    pub(super) fn is_suspend_key(key: &KeyEvent) -> bool {
        key.code == KeyCode::Char('z') && key.modifiers.contains(KeyModifiers::CONTROL)
    }

    /// Mark selection-relevant state as changed (see `state_gen`).
    pub(super) fn touch(&mut self) {
        self.state_gen = self.state_gen.wrapping_add(1);
    }

    pub(super) fn handle_key(&mut self, key: &KeyEvent) {
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
        // `d` toggles the diagnostics overlay from anywhere.
        if no_ctrl_alt && matches!(key.code, KeyCode::Char('d') | KeyCode::Char('D')) {
            self.view_state.show_diagnostics = !self.view_state.show_diagnostics;
            if self.view_state.show_diagnostics {
                self.layout.diagnostics_scroll.set(0);
                self.layout.diagnostics_hscroll.set(0);
                // The overlay owns all input while open: drop any active
                // resize so borders behind it never glow.
                self.view_state.drag = DragMode::None;
                self.view_state.hover.set(DragMode::None);
            }
            return;
        }
        // While the overlay is open it owns every key except Ctrl+C:
        // `d`/`Esc` closes, `q` quits, the rest scrolls. Uppercase and
        // lowercase + SHIFT report the same intent on all protocols.
        if self.view_state.show_diagnostics {
            match key.code {
                KeyCode::Esc => self.view_state.show_diagnostics = false,
                KeyCode::Char('q') => self.running = false,
                KeyCode::Up | KeyCode::Char('k') | KeyCode::Char('K') => {
                    self.scroll_diagnostics(-1)
                }
                KeyCode::Down | KeyCode::Char('j') | KeyCode::Char('J') => {
                    self.scroll_diagnostics(1)
                }
                KeyCode::Home => self.scroll_diagnostics_edge(true),
                KeyCode::End => self.scroll_diagnostics_edge(false),
                KeyCode::PageUp | KeyCode::Char('b') => self.page_diagnostics(-1),
                KeyCode::PageDown | KeyCode::Char('f') | KeyCode::Char(' ') => {
                    self.page_diagnostics(1)
                }
                // Horizontal pan over long values (key column stays
                // frozen): Ctrl jumps ten chars, `0` jumps back.
                KeyCode::Left | KeyCode::Char('h') | KeyCode::Char('H') => self
                    .scroll_diagnostics_h(if key.modifiers.contains(KeyModifiers::CONTROL) {
                        -10
                    } else {
                        -1
                    }),
                KeyCode::Right | KeyCode::Char('l') | KeyCode::Char('L') => self
                    .scroll_diagnostics_h(if key.modifiers.contains(KeyModifiers::CONTROL) {
                        10
                    } else {
                        1
                    }),
                KeyCode::Char('0') => self.layout.diagnostics_hscroll.set(0),
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
                self.view_state.focus = match self.view_state.focus {
                    Focus::Services => Focus::Answers,
                    Focus::Answers => Focus::Questions,
                    Focus::Questions => Focus::Hex,
                    Focus::Hex => Focus::Services,
                };
                self.snap_detail_to_focus();
                return;
            }
            KeyCode::BackTab => {
                self.view_state.focus = match self.view_state.focus {
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
    pub(super) fn clamp_left_pct(pct: u16) -> u16 {
        pct.clamp(15, 80)
    }

    /// Answers/Questions shares keep at least 10% each and leave at least
    /// 10% for the hex pane (`answers + questions <= 90`). The second
    /// argument is the other share.
    pub(super) fn clamp_pane_pct(pct: u16, others: u16) -> u16 {
        let max = 90u16.saturating_sub(others).max(10);
        pct.clamp(10, 70).min(max)
    }

    pub(super) fn pct_from_x(col: u16, body: Rect) -> u16 {
        if body.width == 0 {
            return 33;
        }
        (col.saturating_sub(body.x) as u32 * 100 / body.width.max(1) as u32).min(100) as u16
    }

    pub(super) fn pct_from_y(row: u16, right: Rect) -> u16 {
        if right.height == 0 {
            return 34;
        }
        (row.saturating_sub(right.y) as u32 * 100 / right.height.max(1) as u32).min(100) as u16
    }

    pub(super) fn point_in(rect: Rect, col: u16, row: u16) -> bool {
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
    pub(super) fn divider_at(&self, col: u16, row: u16) -> DragMode {
        let left = self.layout.left_rect.get();
        let right = self.layout.right_rect.get();
        if left.width > 0 && right.width > 0 {
            let left_edge = left.x.saturating_add(left.width.saturating_sub(1));
            if (col == left_edge || col == right.x)
                && row >= left.y
                && row < left.y.saturating_add(left.height)
            {
                return DragMode::Vertical;
            }
        }
        let answers = self.layout.answers_rect.get();
        let questions = self.layout.questions_rect.get();
        if answers.height > 0 && questions.height > 0 {
            let bottom = answers.y.saturating_add(answers.height.saturating_sub(1));
            if (row == bottom || row == questions.y)
                && col >= answers.x
                && col < answers.x.saturating_add(answers.width)
            {
                return DragMode::HorizUpper;
            }
        }
        let hex = self.layout.hex_rect.get();
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

    pub(super) fn set_left_from_x(&mut self, col: u16) {
        let pct = Self::pct_from_x(col, self.layout.body_rect.get());
        self.view_state.left_pct = Self::clamp_left_pct(pct);
    }

    pub(super) fn set_answers_from_y(&mut self, row: u16) {
        let pct = Self::pct_from_y(row, self.layout.right_rect.get());
        self.view_state.answers_pct = Self::clamp_pane_pct(pct, self.view_state.questions_pct);
    }

    pub(super) fn set_questions_from_y(&mut self, row: u16) {
        let combined = Self::pct_from_y(row, self.layout.right_rect.get());
        let want = combined.saturating_sub(self.view_state.answers_pct);
        self.view_state.questions_pct = Self::clamp_pane_pct(want, self.view_state.answers_pct);
    }

    pub(super) fn handle_mouse(&mut self, mouse: &MouseEvent) {
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
                self.view_state.drag = DragMode::None;
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
    /// viewport. The diagnostics overlay owns the wheel while open.
    pub(super) fn mouse_wheel(&mut self, delta: isize) {
        if self.view_state.show_diagnostics {
            self.scroll_diagnostics(delta);
            return;
        }
        match self.view_state.focus {
            Focus::Services => self.move_selection(delta),
            Focus::Answers | Focus::Questions => self.move_detail_cursor(delta),
            Focus::Hex => self.scroll_hex(delta),
        }
    }

    /// Horizontal wheel notch: pans diagnostics values while the overlay is
    /// open, ignored everywhere else.
    pub(super) fn mouse_hwheel(&mut self, delta: isize) {
        if self.view_state.show_diagnostics {
            self.scroll_diagnostics_h(delta);
        }
    }

    pub(super) fn mouse_down(&mut self, col: u16, row: u16) {
        // The diagnostics overlay owns all input while open (closed via d/Esc).
        if self.view_state.show_diagnostics {
            return;
        }
        match self.divider_at(col, row) {
            DragMode::None => {}
            mode => {
                self.view_state.drag = mode;
                self.view_state.hover.set(mode);
                return;
            }
        }
        if Self::point_in(self.layout.left_rect.get(), col, row) {
            self.click_service_list(row);
        } else if Self::point_in(self.layout.answers_rect.get(), col, row) {
            self.click_answers(row);
        } else if Self::point_in(self.layout.questions_rect.get(), col, row) {
            self.click_questions(row);
        } else if Self::point_in(self.layout.hex_rect.get(), col, row) {
            // The hex pane follows the cursor; clicking focuses it so its
            // keys scroll the dump.
            self.view_state.focus = Focus::Hex;
            self.click_hex_field(col, row);
        }
    }

    pub(super) fn click_hex_field(&self, col: u16, row: u16) {
        if let Some((_, index)) = self
            .layout
            .hex_field_hits
            .borrow()
            .iter()
            .find(|(rect, _)| col >= rect.x && col < rect.x + rect.width && row == rect.y)
        {
            self.view_state.hex_selected_field.set(Some(*index));
        }
    }

    pub(super) fn mouse_drag(&mut self, col: u16, row: u16) {
        // The diagnostics overlay owns all input while open (closed via d/Esc).
        if self.view_state.show_diagnostics {
            return;
        }
        match self.view_state.drag {
            DragMode::Vertical => {
                self.set_left_from_x(col);
                self.view_state.hover.set(DragMode::Vertical);
            }
            DragMode::HorizUpper => {
                self.set_answers_from_y(row);
                self.view_state.hover.set(DragMode::HorizUpper);
            }
            DragMode::HorizLower => {
                self.set_questions_from_y(row);
                self.view_state.hover.set(DragMode::HorizLower);
            }
            DragMode::None => {
                self.view_state.hover.set(self.divider_at(col, row));
            }
        }
    }

    pub(super) fn mouse_moved(&mut self, col: u16, row: u16) {
        // The diagnostics overlay owns all input while open (closed via d/Esc).
        if self.view_state.show_diagnostics {
            return;
        }
        // Some terminals report drags as Moved; keep following the active
        // divider in that case.
        if self.view_state.drag != DragMode::None {
            self.mouse_drag(col, row);
        } else {
            self.view_state.hover.set(self.divider_at(col, row));
        }
    }

    /// Click in the Hosts pane: instances select, headers fold. Mirrors the
    /// keyboard rule that expanded headers are not selectable stops.
    pub(super) fn click_service_list(&mut self, row: u16) {
        self.view_state.focus = Focus::Services;
        let area = self.layout.left_rect.get();
        if area.height < 3
            || row <= area.y
            || row >= area.y.saturating_add(area.height).saturating_sub(1)
        {
            return;
        }
        let rel = row.saturating_sub(area.y.saturating_add(1)) as usize;
        let idx = self.layout.list_offset.get().saturating_add(rel);
        let items = self.display_items();
        let Some(item) = items.get(idx) else {
            return;
        };
        match item {
            DisplayItem::Instance { .. } | DisplayItem::Enum { .. } | DisplayItem::Unattributed => {
                self.view_state.selected_display = idx;
                self.clamp_selection();
            }
            DisplayItem::Host { label } => {
                let label = label.clone();
                // Capture the selected item first: folding below the cursor
                // removes rows and unfolding above it inserts them, so the
                // raw index is stale after the toggle either way.
                let prev = items.get(self.view_state.selected_display).cloned();
                if !self.collapsed_hosts.remove(&label) {
                    self.collapsed_hosts.insert(label);
                }
                let items = self.display_items();
                let mut restored = false;
                if let Some(p) = prev {
                    if let Some(pos) = items.iter().position(|it| *it == p) {
                        // Same item, new row: selecting the clicked header
                        // can wait for clamp_selection below.
                        self.view_state.selected_display = pos;
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
                    self.view_state.selected_display = idx;
                }
                self.clamp_selection();
            }
        }
    }

    /// Map an Answers table row (including info/child rows) to the detail
    /// cursor index. Child rows select their parent record; info rows
    /// select nothing. Mirrors `detail_table_rows` in `ui.rs`.
    pub(super) fn answers_table_row_to_detail(&self, table_row: usize) -> Option<usize> {
        // Finding and TXT child rows select their parent record, info and
        // block rows nothing. Hit-test the frame as drawn: findings can
        // change between drawing and the click.
        if let Some(rows) = self.layout.answers_rows.borrow().as_ref() {
            return rows.get(table_row).copied().flatten();
        }
        // Nothing drawn for this target yet: the current layout.
        let target = self.display_detail()?;
        let found = self.anomalies();
        self.answers_layout(&target, &found)
            .get(table_row)?
            .owning_record()
    }

    pub(super) fn click_answers(&mut self, row: u16) {
        self.view_state.focus = Focus::Answers;
        let area = self.layout.answers_rect.get();
        if area.height < 3 || row < area.y.saturating_add(2) {
            return;
        }
        if row >= area.y.saturating_add(area.height).saturating_sub(1) {
            return;
        }
        let rel = row.saturating_sub(area.y.saturating_add(2)) as usize;
        let table_row = self.layout.detail_offset.get().saturating_add(rel);
        if let Some(idx) = self.answers_table_row_to_detail(table_row) {
            // Stay on the clicked target: the cursor follows the click
            // instead of the manual-scroll viewport. A new row also
            // restarts the hex dump at the top.
            self.view_state.detail_free_scroll = false;
            if self.view_state.detail_selected != idx {
                self.view_state.detail_selected = idx;
                self.restart_for_new_row();
            }
            self.detail_anchor = self
                .display_detail()
                .and_then(|d| Self::identity_at_detail(&d, self.view_state.detail_selected));
        }
    }

    pub(super) fn click_questions(&mut self, row: u16) {
        self.view_state.focus = Focus::Questions;
        let area = self.layout.questions_rect.get();
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
        let table_row = self.layout.questions_offset.get().saturating_add(rel);
        // Each question row is followed by its finding rows (#248); hit
        // the frame as drawn, else the current layout.
        let drawn = self
            .layout
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
            self.view_state.detail_free_scroll = false;
            let idx = raws + question;
            if self.view_state.detail_selected != idx {
                self.view_state.detail_selected = idx;
                self.restart_for_new_row();
            }
            self.detail_anchor = self
                .display_detail()
                .and_then(|d| Self::identity_at_detail(&d, self.view_state.detail_selected));
        }
    }

    /// Cursor keys routed to the focused pane. Tab switches panes; arrows
    /// and j/k navigate inside the focused pane.
    pub(super) fn handle_focused_key(&mut self, key: &KeyEvent) {
        match self.view_state.focus {
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
    pub(super) fn is_selectable(&self, item: &DisplayItem) -> bool {
        match item {
            DisplayItem::Instance { .. } | DisplayItem::Enum { .. } | DisplayItem::Unattributed => {
                true
            }
            DisplayItem::Host { label } => self.collapsed_hosts.contains(label),
        }
    }

    /// First/last selectable stop.
    pub(super) fn select_edge(&mut self, first: bool) {
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
            self.view_state.selected_display = i;
        }
    }

    /// Page the service selection by one viewport of stops
    /// (PageUp/PageDown/b/f/Space). Falls back to 10 stops before the
    /// first draw answers the real height.
    pub(super) fn page_selection(&mut self, pages: isize) {
        let per_page = self.layout.list_viewport.get().max(1) as isize;
        let steps = pages * per_page;
        let n = steps.unsigned_abs().min(1000);
        for _ in 0..n {
            let before = self.view_state.selected_display;
            self.move_selection(steps.signum());
            if self.view_state.selected_display == before {
                break;
            }
        }
    }

    /// Host group keys in display order.
    pub(super) fn group_labels(&self) -> Vec<String> {
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
    pub(super) fn cursor_group(&self) -> Option<String> {
        match self.display_items().get(self.view_state.selected_display)? {
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
    pub(super) fn jump_group(&mut self, delta: isize) {
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
    pub(super) fn jump_group_edge(&mut self, first: bool) {
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
    pub(super) fn select_group_first(&mut self, label: &str) {
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
                self.view_state.selected_display = i;
                return;
            }
        }
    }

    pub(super) fn move_selection(&mut self, delta: isize) {
        let items = self.display_items();
        if items.is_empty() {
            self.view_state.selected_display = 0;
            return;
        }
        let max = items.len().saturating_sub(1);
        // Entries can vanish between frames on time alone (an expiring
        // `(unattributed)` group): never index past the rebuilt list.
        let mut cur = self.view_state.selected_display.min(max);

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
                self.view_state.selected_display = cur;
                return;
            }
        }
    }

    /// Index range of the focused record table inside the combined
    /// [answers, questions] cursor order: Answers covers the raw answers,
    /// Questions the question rows. Services focus is unused by the
    /// record cursor; it spans everything. Hex has no cursor rows.
    pub(super) fn detail_range(&self) -> (usize, usize) {
        let (raws, total) = self
            .display_detail()
            .map(|d| {
                (
                    d.ordered_answers().len(),
                    d.ordered_answers().len() + d.questions_len(),
                )
            })
            .unwrap_or((0, 0));
        match self.view_state.focus {
            Focus::Answers => (0, raws),
            Focus::Questions => (raws, total),
            Focus::Services => (0, total),
            Focus::Hex => (0, 0),
        }
    }

    /// Snap the cursor into the newly focused table (first row), keeping
    /// it where it is when already inside.
    pub(super) fn snap_detail_to_focus(&mut self) {
        self.sync_detail_cursor();
        let before = self.view_state.detail_selected;
        let (lo, hi) = self.detail_range();
        if hi > lo
            && (self.view_state.detail_selected < lo || self.view_state.detail_selected >= hi)
        {
            self.view_state.detail_selected = lo;
        }
        // New row means new hex bytes: restart the dump at the top.
        if self.view_state.detail_selected != before {
            self.restart_for_new_row();
        }
        self.detail_anchor = self
            .display_detail()
            .and_then(|d| Self::identity_at_detail(&d, self.view_state.detail_selected));
    }

    /// Record cursor over the focused table: raw answers for Answers,
    /// question rows for Questions. The cursor tracks row identity, so
    /// TTL resorting and re-announcements don't yank the selection to
    /// another row.
    pub(super) fn move_detail_cursor(&mut self, delta: isize) {
        self.sync_detail_cursor();
        // Resuming cursor-follow: manual scroll ends once the cursor moves.
        self.view_state.detail_free_scroll = false;
        let before = self.view_state.detail_selected;
        let (lo, hi) = self.detail_range();
        if hi <= lo {
            return;
        }
        if self.view_state.detail_selected < lo || self.view_state.detail_selected >= hi {
            self.view_state.detail_selected = if delta < 0 { hi - 1 } else { lo };
        } else if delta > 0 {
            if self.view_state.detail_selected + 1 < hi {
                self.view_state.detail_selected += 1;
            }
        } else if delta < 0 && self.view_state.detail_selected > lo {
            self.view_state.detail_selected -= 1;
        }
        self.detail_anchor = self
            .display_detail()
            .and_then(|d| Self::identity_at_detail(&d, self.view_state.detail_selected));
        // New row means new hex bytes: restart the dump at the top.
        if self.view_state.detail_selected != before {
            self.restart_for_new_row();
        }
    }

    /// First/last row of the focused table.
    pub(super) fn move_detail_edge(&mut self, first: bool) {
        self.sync_detail_cursor();
        self.view_state.detail_free_scroll = false;
        let before = self.view_state.detail_selected;
        let (lo, hi) = self.detail_range();
        // An empty focused table has no edge row: keep the selection and
        // its anchor, like `move_detail_cursor`.
        if hi <= lo {
            return;
        }
        self.view_state.detail_selected = if first { lo } else { hi - 1 };
        self.detail_anchor = self
            .display_detail()
            .and_then(|d| Self::identity_at_detail(&d, self.view_state.detail_selected));
        if self.view_state.detail_selected != before {
            self.restart_for_new_row();
        }
    }

    /// Page the record cursor by one Answers-table viewport. Falls back
    /// to 10 rows before the first draw answers the real height.
    pub(super) fn page_detail(&mut self, pages: isize) {
        let per_page = self.layout.record_viewport.get().max(1) as isize;
        let steps = pages * per_page;
        let n = steps.unsigned_abs().min(1000);
        for _ in 0..n {
            let before = self.view_state.detail_selected;
            self.move_detail_cursor(steps.signum());
            if self.view_state.detail_selected == before {
                break;
            }
        }
    }

    /// Nudge the Answers viewport without moving the record cursor, and pin
    /// it there until the cursor, selection, or expansion changes. Upper
    /// clamping happens at render time, where the row count is known.
    pub(super) fn scroll_detail(&mut self, delta: isize) {
        let cur = self.layout.detail_offset.get();
        let next = if delta < 0 {
            cur.saturating_sub(delta.unsigned_abs())
        } else {
            cur.saturating_add(delta.unsigned_abs())
        };
        self.layout.detail_offset.set(next);
        self.view_state.detail_free_scroll = true;
    }

    /// Scroll the focused detail viewport: the Hex dump while it holds
    /// focus, otherwise the Answers table (which also scrolls from the
    /// Services and Questions panes).
    pub(super) fn scroll_focused_detail(&mut self, delta: isize) {
        if self.view_state.focus == Focus::Hex {
            self.scroll_hex(delta);
        } else {
            self.scroll_detail(delta);
        }
    }

    /// Nudge a cursorless viewport offset, saturating at zero. Upper
    /// clamping happens at render time, where the line count is known.
    /// Shared by the Hex and diagnostics panes.
    pub(super) fn bump_offset(offset: &Cell<usize>, delta: isize) {
        let cur = offset.get();
        let next = if delta < 0 {
            cur.saturating_sub(delta.unsigned_abs())
        } else {
            cur.saturating_add(delta.unsigned_abs())
        };
        offset.set(next);
    }

    /// Page a cursorless viewport by viewportfuls.
    pub(super) fn page_offset(viewport: &Cell<usize>, pages: isize) -> isize {
        viewport.get().max(1) as isize * pages
    }

    /// Nudge the Hex viewport; the dump follows the record cursor, so
    /// there is no cursor to resume and no pin flag.
    pub(super) fn scroll_hex(&mut self, delta: isize) {
        Self::bump_offset(&self.layout.hex_offset, delta);
    }

    pub(super) fn scroll_hex_edge(&mut self, first: bool) {
        if first {
            self.layout.hex_offset.set(0);
        } else {
            self.layout.hex_offset.set(usize::MAX / 2);
        }
    }

    pub(super) fn page_hex(&mut self, pages: isize) {
        let steps = Self::page_offset(&self.layout.hex_viewport, pages);
        self.scroll_hex(steps);
    }

    /// New detail row: restart the hex dump at the top.
    pub(super) fn restart_for_new_row(&mut self) {
        self.layout.hex_offset.set(0);
        self.view_state.hex_selected_field.set(None);
        self.layout.hex_field_hits.borrow_mut().clear();
    }

    /// Scroll the diagnostics overlay; upper clamping happens at render time.
    pub(super) fn scroll_diagnostics(&mut self, delta: isize) {
        Self::bump_offset(&self.layout.diagnostics_scroll, delta);
    }

    pub(super) fn scroll_diagnostics_edge(&mut self, first: bool) {
        if first {
            self.layout.diagnostics_scroll.set(0);
        } else {
            self.layout.diagnostics_scroll.set(usize::MAX / 2);
        }
    }

    pub(super) fn page_diagnostics(&mut self, pages: isize) {
        let steps = Self::page_offset(&self.layout.diagnostics_viewport, pages);
        self.scroll_diagnostics(steps);
    }

    /// Pan the diagnostics overlay horizontally (chars); upper clamping
    /// happens at render time against the longest value.
    pub(super) fn scroll_diagnostics_h(&mut self, delta: isize) {
        Self::bump_offset(&self.layout.diagnostics_hscroll, delta);
    }

    /// Identity of the table row at an index (raw answers first, then
    /// questions by type/newest-first, matching the rendered table).
    pub(super) fn identity_at_detail(
        target: &DetailTarget<'_>,
        index: usize,
    ) -> Option<DetailCursorKey> {
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
    pub(super) fn position_of_detail(
        target: &DetailTarget<'_>,
        key: &DetailCursorKey,
    ) -> Option<usize> {
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
    pub(super) fn sync_detail_cursor(&mut self) {
        let svc_key = self
            .selected_service()
            .map(|s| (s.service_type.clone(), s.instance.clone()));
        let enum_key = self.selected_enum().map(|e| e.name.clone());
        let unattributed = self.unattributed_selected();
        if svc_key.is_none() && enum_key.is_none() && !unattributed {
            // Headers select no row: no field stays highlighted.
            self.view_state.hex_selected_field.set(None);
            self.layout.hex_field_hits.borrow_mut().clear();
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
            self.layout.answers_rows.replace(None);
            self.layout.questions_rows.replace(None);
            self.view_state.detail_selected = 0;
            self.layout.detail_offset.set(0);
            self.view_state.detail_free_scroll = false;
            self.layout.questions_offset.set(0);
            self.restart_for_new_row();
            self.detail_anchor = self
                .display_detail()
                .and_then(|d| Self::identity_at_detail(&d, self.view_state.detail_selected));
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
            (Some(pos), _) => self.view_state.detail_selected = pos,
            (None, Some(_)) => {
                // Tracked row expired away (capped question list): park on
                // the last raw record instead of pointing at shifted churn.
                self.view_state.hex_selected_field.set(None);
                self.layout.hex_field_hits.borrow_mut().clear();
                let parked = self
                    .display_detail()
                    .map(|d| d.ordered_answers().len().saturating_sub(1))
                    .unwrap_or(0);
                self.view_state.detail_selected = parked;
                self.detail_anchor = self
                    .display_detail()
                    .and_then(|d| Self::identity_at_detail(&d, self.view_state.detail_selected));
            }
            (None, None) => {}
        }
        // Clamp against entries that aged away (capped question list).
        let max = self
            .display_detail()
            .map(|d| (d.ordered_answers().len() + d.questions_len()).saturating_sub(1))
            .unwrap_or(0);
        if self.view_state.detail_selected > max {
            self.view_state.detail_selected = max;
        }
    }

    pub(super) fn clamp_selection(&mut self) {
        let items = self.display_items();
        let max = items.len().saturating_sub(1);
        if self.view_state.selected_display > max {
            self.view_state.selected_display = max;
        }
        // Expanded headers are not selectable stops (e.g. after a collapse
        // stranded the cursor on one, or at startup); settle on an instance.
        // Collapsed headers stay put so their host can be unfolded again.
        if matches!(
            self.display_items().get(self.view_state.selected_display),
            Some(DisplayItem::Host { label }) if !self.is_host_collapsed(label)
        ) {
            self.move_selection(1);
        }
        if matches!(
            self.display_items().get(self.view_state.selected_display),
            Some(DisplayItem::Host { label }) if !self.is_host_collapsed(label)
        ) {
            self.move_selection(-1);
        }
        if self.view_state.selected_display < self.layout.list_offset.get() {
            self.layout
                .list_offset
                .set(self.view_state.selected_display);
        }
        if self.layout.list_offset.get() > max {
            self.layout.list_offset.set(max.saturating_sub(1));
        }
        // The first header is not a selectable stop, so plain
        // follow-the-cursor scrolling would strand the viewport at
        // offset 1 with row 0 hidden forever. When the cursor sits on
        // the first selectable row, pull the view back to the top.
        if let Some(first) = items.iter().position(|it| self.is_selectable(it)) {
            if self.view_state.selected_display == first {
                let top = first.saturating_sub(1);
                if self.layout.list_offset.get() > top {
                    self.layout.list_offset.set(top);
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

    /// Toggle the TXT record under the Tab cursor. Returns false when the
    /// cursor is not on an expandable TXT row (caller falls back to the
    /// host fold). Headers select nothing, so `Enter` on a header
    /// keeps folding the host instead of touching TXT state.
    pub(super) fn toggle_txt_expanded(&mut self) -> bool {
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
        self.view_state.detail_free_scroll = false;
        true
    }
}
