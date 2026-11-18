// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use ratatui::layout::Rect;
use std::cell::{Cell, RefCell};

/// What the last frame measured or clamped, shared between draw and input.
///
/// `ui` records pane geometry, viewport heights, row maps and hex hit
/// boxes here while drawing, and clamps the scroll offsets that input
/// moves. Input reads it for mouse hit-testing and paging. It is the only
/// state draw writes, through `Cell`/`RefCell`.
#[derive(Default)]
pub struct Layout {
    pub list_offset: Cell<usize>,
    /// Visible rows of the service list pane (minus borders), recorded
    /// during draw so PageUp/PageDown paging matches the viewport.
    pub list_viewport: Cell<usize>,
    /// Visible rows of the Answers table (minus header/borders), recorded
    /// during draw so paging the record cursor matches the viewport.
    pub record_viewport: Cell<usize>,
    pub detail_offset: Cell<usize>,
    pub questions_offset: Cell<usize>,
    /// Manual scroll of the Hex pane, which follows the record cursor and
    /// has no cursor of its own. Reset when the cursor or target changes;
    /// upper clamping happens at render time, where the line count is known.
    pub hex_offset: Cell<usize>,
    /// Visible rows of the Hex pane (minus borders), recorded during draw
    /// so paging matches the viewport.
    pub hex_viewport: Cell<usize>,
    /// Last-frame geometry for mouse hit-testing (recorded during draw).
    pub body_rect: Cell<Rect>,
    pub left_rect: Cell<Rect>,
    pub right_rect: Cell<Rect>,
    pub answers_rect: Cell<Rect>,
    pub questions_rect: Cell<Rect>,
    pub hex_rect: Cell<Rect>,
    pub hex_field_hits: RefCell<Vec<(Rect, usize)>>,
    /// Scroll offset inside the metrics popup (viewport recorded at draw).
    pub metrics_scroll: Cell<usize>,
    pub metrics_viewport: Cell<usize>,
    /// Horizontal scroll offset inside the metrics popup, in chars: the
    /// key column stays frozen while long values pan left.
    pub metrics_hscroll: Cell<usize>,
    /// Row -> record index of the Answers table as last drawn (`None` per
    /// info, block or unowned row), so a click hits what was on screen
    /// even if findings changed since. `None` before the first draw.
    pub answers_rows: RefCell<Option<Vec<Option<usize>>>>,
    /// Row -> question index of the Questions table as last drawn.
    pub questions_rows: RefCell<Option<Vec<Option<usize>>>>,
}
