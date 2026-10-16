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

//! Layout arithmetic over `Rect`. Every function saturates and never panics.

use crate::decorations::Rect;

/// Shrinks every side by `d`. The origin moves in by `d`; a width or height
/// smaller than `2 * d` collapses to zero.
pub fn inset(r: Rect, d: u32) -> Rect {
    let d2 = d.saturating_mul(2);
    Rect {
        x: r.x.saturating_add(d),
        y: r.y.saturating_add(d),
        w: r.w.saturating_sub(d2),
        h: r.h.saturating_sub(d2),
    }
}

/// Splits off a left part `w` wide, clamped to `r.w`, and returns it with the
/// remainder.
pub fn split_left(r: Rect, w: u32) -> (Rect, Rect) {
    let w = w.min(r.w);
    let left = Rect { w, ..r };
    let rest = Rect { x: r.x.saturating_add(w), w: r.w - w, ..r };
    (left, rest)
}

/// Splits off a top part `h` tall, clamped to `r.h`, and returns it with the
/// remainder.
pub fn split_top(r: Rect, h: u32) -> (Rect, Rect) {
    let h = h.min(r.h);
    let top = Rect { h, ..r };
    let rest = Rect { y: r.y.saturating_add(h), h: r.h - h, ..r };
    (top, rest)
}

/// A `w` by `h` rect centred in `outer`, with `w` and `h` clamped to it.
pub fn centre(outer: Rect, w: u32, h: u32) -> Rect {
    let w = w.min(outer.w);
    let h = h.min(outer.h);
    Rect {
        x: outer.x.saturating_add((outer.w - w) / 2),
        y: outer.y.saturating_add((outer.h - h) / 2),
        w,
        h,
    }
}

/// Whether the point lies in `r`, half-open on the right and bottom edges.
/// Negative coordinates are outside. Every widget's hit test uses this.
pub fn contains(r: Rect, x: i32, y: i32) -> bool {
    if x < 0 || y < 0 {
        return false;
    }
    let (x, y) = (x as u32, y as u32);
    x >= r.x && y >= r.y && x - r.x < r.w && y - r.y < r.h
}

/// `n` out of `of` as a share of `len`, rounded to the nearest; 0 when `of` is 0.
/// Maps a value to a position along a track and back, for sliders, bars and
/// scroll bars.
pub fn share(n: u32, len: u32, of: u32) -> u32 {
    let (n, len, of) = (u64::from(n), u64::from(len), u64::from(of));
    (n * len + of / 2).checked_div(of).map_or(0, |v| u32::try_from(v).unwrap_or(u32::MAX))
}
