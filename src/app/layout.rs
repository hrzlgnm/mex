// Copyright 2026 hrzlgnm
// SPDX-License-Identifier: MIT

use ratatui::layout::Rect;
use std::cell::{Cell, RefCell};

use super::DetailCursorKey;

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
    /// Scroll offset inside the diagnostics popup (viewport recorded at draw).
    pub diagnostics_scroll: Cell<usize>,
    pub diagnostics_viewport: Cell<usize>,
    /// Horizontal scroll offset inside the diagnostics popup, in chars: the
    /// key column stays frozen while long values pan left.
    pub diagnostics_hscroll: Cell<usize>,
    /// Rows of the Answers table as last drawn (owner: record index),
    /// so a click hits what was on screen even if findings changed
    /// since. `None` before the first draw.
    pub answers_rows: RefCell<Option<DrawnRows>>,
    /// Rows of the Questions table as last drawn (owner: question index).
    pub questions_rows: RefCell<Option<DrawnRows>>,
}

/// One table's rows as drawn: each row's owner (`None` per info, block
/// or unowned row) and its height in lines. Wrapped findings (#410) are
/// taller than one line, so screen lines and table rows differ.
///
/// Owners are identities, not list positions, so a reorder between the
/// draw and a click can't retarget a row (#413). Each identity is held
/// once in `keys`; rows point at it, so the many child rows of one
/// record (findings, expanded TXT pairs) don't each clone its rdata.
#[derive(Debug, Clone, Default)]
pub struct DrawnRows {
    keys: Vec<DetailCursorKey>,
    owners: Vec<Option<usize>>,
    heights: Vec<u16>,
}

impl DrawnRows {
    /// Rows owned by `keys[owner]`, with their heights; a missing height
    /// counts as 1.
    pub fn new(
        keys: Vec<DetailCursorKey>,
        owners: Vec<Option<usize>>,
        mut heights: Vec<u16>,
    ) -> Self {
        heights.resize(owners.len(), 1);
        Self {
            keys,
            owners,
            heights,
        }
    }

    /// Owner of table row `row`.
    pub fn owner(&self, row: usize) -> Option<&DetailCursorKey> {
        self.keys.get(self.owners.get(row).copied().flatten()?)
    }

    /// Table row drawn at viewport line `line` while the table shows
    /// rows from `offset` on, or `None` past the last row.
    pub fn row_at_line(&self, offset: usize, line: usize) -> Option<usize> {
        let mut top = 0;
        for (row, h) in self.heights.iter().enumerate().skip(offset) {
            let h = usize::from((*h).max(1));
            if line < top + h {
                return Some(row);
            }
            top += h;
        }
        None
    }

    /// Lines between the rows of owners `a` and `b` (each owner's first
    /// row, its own row), `None` when either has no row.
    pub fn lines_between_owners(&self, a: &DetailCursorKey, b: &DetailCursorKey) -> Option<usize> {
        // Matched like a click resolves them (names fold ASCII case).
        let first = |o: &DetailCursorKey| {
            let key = self.keys.iter().position(|k| k.same_row(o))?;
            self.owners.iter().position(|x| *x == Some(key))
        };
        let (ra, rb) = (first(a)?, first(b)?);
        let (lo, hi) = (ra.min(rb), ra.max(rb));
        Some(self.heights[lo..hi].iter().map(|h| usize::from(*h)).sum())
    }
}
