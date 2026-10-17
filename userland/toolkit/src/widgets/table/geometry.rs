// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

//! Where a table's header, columns and rows sit in `at`, which draw and hit
//! share.

use alloc::vec::Vec;

use super::widths::widths;
use super::Table;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::SPACE;
use crate::widgets::rect::split_top;

/// One column across the table: where it starts and how wide it is, and the
/// part its title and cells are kept to.
#[derive(Clone, Copy)]
pub(super) struct Span {
    pub(super) x: u32,
    pub(super) w: u32,
    pub(super) ink_x: u32,
    pub(super) ink_w: u32,
}

/// The placed parts of a table, in drawing pixels. `rows` holds one rect per
/// given row that fits whole, in order, so the rows past the bottom are left
/// out. `titled` is whether the header has its full height for titles.
pub(super) struct Parts {
    pub(super) head: Rect,
    pub(super) rule: Rect,
    pub(super) body: Rect,
    pub(super) cols: Vec<Span>,
    pub(super) rows: Vec<Rect>,
    pub(super) titled: bool,
}

impl Table<'_> {
    /// The header takes a row's height at the top of `at`, a hairline rule
    /// sits under it and the body takes the rest, the rows stacked from its
    /// top. The columns tile `at.w` with no gap, as `widths` shares it, and
    /// each keeps its ink `SPACE.md` in from both its edges, or half its
    /// width when narrower.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let (s, row_h) = (scale(), Self::row_h());
        let (head, rest) = split_top(at, row_h);
        let (rule, body) = split_top(rest, s.hair());
        let pad = s.px(u32::from(SPACE.md));
        let span = |x: &mut u32, w: u32| {
            let (p, at_x) = (pad.min(w / 2), *x);
            *x = x.saturating_add(w);
            Some(Span { x: at_x, w, ink_x: at_x.saturating_add(p), ink_w: w - p * 2 })
        };
        let cols = widths(self.cols, at.w).into_iter().scan(at.x, span).collect();
        let n = u32::try_from(self.rows.len()).unwrap_or(u32::MAX).min(body.h / row_h.max(1));
        let place = |k: u32| Rect { y: body.y.saturating_add(k * row_h), h: row_h, ..body };
        let rows = (0..n).map(place).collect();
        Parts { head, rule, body, cols, rows, titled: head.h == row_h }
    }
}
