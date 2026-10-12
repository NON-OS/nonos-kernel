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

use super::rect::Rect;
use super::start_geom::StartGeom;

pub(super) const CELL_W: i32 = 112;
pub(super) const CELL_H: i32 = 100;
const SIDE: i32 = 32;
const TEXT_X: i32 = 52;
const TEXT_END: i32 = 28;
const CARDS_MAX_W: i32 = 1000;
const CARD_GAP: i32 = 20;
const CARD_H: i32 = 204;
const CARD_MIN_W: i32 = 240;

/// The start page's three cards from `top`: side by side when each can be
/// `CARD_MIN_W` wide in a `w` wide page, else stacked.
pub(super) fn cards(w: i32, top: i32) -> [Rect; 3] {
    let avail = CARDS_MAX_W.min((w - 2 * SIDE).max(0));
    let x0 = (w - avail) / 2;
    let cw = (avail - 2 * CARD_GAP) / 3;
    let step = CARD_H + CARD_GAP;
    match cw >= CARD_MIN_W {
        true => {
            core::array::from_fn(|i| Rect::new(x0 + i as i32 * (cw + CARD_GAP), top, cw, CARD_H))
        }
        false => core::array::from_fn(|i| Rect::new(x0, top + i as i32 * step, avail, CARD_H)),
    }
}

/// The cell for favourite `i`: the tile on top, its label under it.
pub fn fav_rect(g: &StartGeom, i: usize) -> Rect {
    let row_w = g.cols * CELL_W;
    let x0 = (g.hero.w - row_w) / 2;
    let (col, row) = (i as i32 % g.cols, i as i32 / g.cols);
    Rect::new(x0 + col * CELL_W, g.tiles_y + row * CELL_H, CELL_W, CELL_H)
}

pub fn fav_at(g: &StartGeom, x: i32, y: i32) -> Option<usize> {
    (0..g.favs).find(|&i| fav_rect(g, i).contains(x, y))
}

/// The search pill's text box, short of its glyph and its rounded end. None
/// while the pill is scrolled past the top or too narrow to hold text.
pub fn pill_text(g: &StartGeom) -> Option<Rect> {
    let p = g.pill;
    let t = Rect::new(p.x + TEXT_X, p.y, p.w - TEXT_X - TEXT_END, p.h);
    (p.y >= 0 && t.w > 0).then_some(t)
}
