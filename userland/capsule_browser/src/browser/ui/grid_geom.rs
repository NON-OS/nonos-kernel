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

use super::list_geom::{ListGeom, BAND_H, BOTTOM};
use super::rect::Rect;

const GAP: i32 = 20;
const CARD_H: i32 = 196;
const MIN_W: i32 = 200;
const CLOSE: i32 = 28;
const CLOSE_INSET: i32 = 10;
const CHIP_H: i32 = 30;
const CHIP_INSET: i32 = 24;

impl ListGeom {
    /// Four columns of cards, or three, two or one as the page narrows.
    pub fn cols(&self) -> i32 {
        (1..=4).rev().find(|&c| c * MIN_W + (c - 1) * GAP <= self.frame.w).unwrap_or(1)
    }

    pub fn grid_rect(&self, i: usize, cols: i32) -> Rect {
        let cols = cols.max(1);
        let cw = ((self.frame.w - (cols - 1) * GAP) / cols).max(0);
        let (col, row) = (i as i32 % cols, i as i32 / cols);
        let y = BAND_H - self.scroll + row * (CARD_H + GAP);
        Rect::new(self.frame.x + col * (cw + GAP), y, cw, CARD_H)
    }

    /// The card of `n` under `(x, y)`; nothing under the header band hits.
    pub fn grid_at(&self, x: i32, y: i32, n: usize, cols: i32) -> Option<usize> {
        if y < BAND_H {
            return None;
        }
        (0..n).find(|&i| self.grid_rect(i, cols).contains(x, y))
    }

    /// The height of the whole page when its grid holds `n` cards.
    pub fn grid_h(&self, n: usize, cols: i32) -> i32 {
        let rows = (n as i32 + cols.max(1) - 1) / cols.max(1);
        BAND_H + rows * CARD_H + (rows - 1).max(0) * GAP + BOTTOM
    }
}

/// The close button in the top right corner of a grid card.
pub fn close_rect(card: Rect) -> Rect {
    Rect::new(card.right() - CLOSE - CLOSE_INSET, card.y + CLOSE_INSET, CLOSE, CLOSE)
}

/// The group chip at the bottom left of a grid card, `w` wide at most.
pub fn chip_rect(card: Rect, w: i32) -> Rect {
    let w = w.min(card.w - 2 * CHIP_INSET).max(0);
    Rect::new(card.x + CHIP_INSET, card.bottom() - CHIP_INSET - CHIP_H, w, CHIP_H)
}
