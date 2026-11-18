// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use std::cell::Cell;

use super::{DragMode, Focus};

/// What the user is looking at: focus, selection, pane splits, drag and
/// hover, and the metrics overlay.
///
/// Only input handling changes it; `ui` reads it through
/// `App::view_state()`.
pub struct ViewState {
    pub selected_display: usize,
    /// Which pane the cursor keys act on. Tab switches panes; arrows and
    /// j/k navigate inside the focused pane.
    pub focus: Focus,
    pub detail_selected: usize,
    /// Manual scroll of the Answers table (`Ctrl-j/k`): while set, the
    /// viewport stays where the user put it instead of following the
    /// `j/k` cursor, so arbitrarily tall TXT expansions can be paged
    /// through. Any cursor or fold action clears it.
    pub detail_free_scroll: bool,
    /// Currently selected field in the displayed resource record.
    pub hex_selected_field: Cell<Option<usize>>,
    /// Horizontal split: percent of the body width given to the Hosts pane.
    /// The shared pane borders are the mouse-drag handles.
    pub left_pct: u16,
    /// Vertical split of the right stack: percent of its height given to
    /// Answers and Questions (the hex pane takes the remainder). The
    /// shared pane borders are mouse-draggable.
    pub answers_pct: u16,
    pub questions_pct: u16,
    /// Active mouse drag; `None` when no button is held on a pane border.
    pub drag: DragMode,
    /// Pane border under the mouse cursor, for highlight. Updated on
    /// `Moved`/`Drag` events; render-only.
    pub hover: Cell<DragMode>,
    /// Metrics overlay popup (`m` toggles, `m`/`Esc` closes).
    pub show_metrics: bool,
}

impl Default for ViewState {
    fn default() -> Self {
        Self {
            selected_display: 0,
            focus: Focus::default(),
            detail_selected: 0,
            detail_free_scroll: false,
            hex_selected_field: Cell::new(None),
            left_pct: 33,
            answers_pct: 50,
            questions_pct: 25,
            drag: DragMode::None,
            hover: Cell::new(DragMode::None),
            show_metrics: false,
        }
    }
}
