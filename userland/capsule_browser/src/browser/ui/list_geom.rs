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

pub use super::list_parts::{max_scroll, middle_pills, trail};
use super::rect::Rect;

pub const BAND_H: i32 = 168;
pub const PILL_H: i32 = 34;
pub const BOTTOM: i32 = 32;
const ROW_H: i32 = 56;
const SIDE: i32 = 40;
const MAX_W: i32 = 960;
const TITLE_Y: i32 = 28;
const SUB_Y: i32 = 78;
const PILLS_Y: i32 = 114;
pub(super) const PILL_GAP: i32 = 8;
const CARD_PAD: i32 = 6;

/// Where an internal page's header, filter pills and list sit, in
/// content-local pixels. The header band stays put; the list under it moves
/// up by `scroll`. The painter and the click handler build it the same way.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ListGeom {
    pub frame: Rect,
    pub title_y: i32,
    pub sub_y: i32,
    pub pills_y: i32,
    pub scroll: i32,
}

impl ListGeom {
    pub fn new(w: i32, h: i32, scroll: i32) -> Self {
        let (w, h) = (w.max(0), h.max(0));
        let fw = MAX_W.min((w - 2 * SIDE).max(0));
        let frame = Rect::new((w - fw) / 2, 0, fw, h);
        ListGeom { frame, title_y: TITLE_Y, sub_y: SUB_Y, pills_y: PILLS_Y, scroll: scroll.max(0) }
    }

    /// Pill `i` of a row whose pills are `widths` wide, left to right.
    pub fn pill(&self, widths: &[i32], i: usize) -> Rect {
        let x = widths.iter().take(i).fold(self.frame.x, |x, w| x + w + PILL_GAP);
        Rect::new(x, self.pills_y, widths.get(i).copied().unwrap_or(0), PILL_H)
    }

    pub fn pill_at(&self, widths: &[i32], x: i32, y: i32) -> Option<usize> {
        (0..widths.len()).find(|&i| self.pill(widths, i).contains(x, y))
    }

    /// The card holding `n` rows.
    pub fn card(&self, n: usize) -> Rect {
        let h = n as i32 * ROW_H + 2 * CARD_PAD;
        Rect::new(self.frame.x, BAND_H - self.scroll, self.frame.w, h)
    }

    pub fn row_rect(&self, i: usize) -> Rect {
        let c = self.card(0);
        Rect::new(c.x, c.y + CARD_PAD + i as i32 * ROW_H, c.w, ROW_H)
    }

    /// The row of a list of `n` under `(x, y)`. Rows scrolled under the
    /// header band are covered by it, so nothing there hits.
    pub fn row_at(&self, x: i32, y: i32, n: usize) -> Option<usize> {
        let top = self.row_rect(0).y;
        if y < BAND_H || y < top || x < self.frame.x || x >= self.frame.right() {
            return None;
        }
        let i = ((y - top) / ROW_H) as usize;
        (i < n).then_some(i)
    }

    /// The height of the whole page when its list has `n` rows.
    pub fn list_h(&self, n: usize) -> i32 {
        BAND_H + self.card(n).h + BOTTOM
    }
}
