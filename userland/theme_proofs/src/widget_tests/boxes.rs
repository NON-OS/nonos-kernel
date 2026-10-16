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

//! The boxes widgets are drawn in, and whether a point falls in one.

use nonos_toolkit::widgets::Rect;

use super::canvas::MARGIN;

/// The width given to a widget with no width of its own.
pub(crate) const FREE_W: u32 = 280;

/// A `w` by `h` box at `MARGIN`, `MARGIN`.
pub(crate) fn boxed(w: u32, h: u32) -> Rect {
    Rect { x: MARGIN, y: MARGIN, w, h }
}

/// Whether the point lies in `r`.
pub(crate) fn inside(r: Rect, (x, y): (u32, u32)) -> bool {
    x >= r.x && y >= r.y && x - r.x < r.w && y - r.y < r.h
}

/// The boxes a widget preferring `size` is drawn in: exactly its size, with
/// room to spare, three quarters as wide and half as wide. A widget with no
/// width of its own gets `FREE_W`.
pub(crate) fn boxes((w, h): (u32, u32)) -> [Rect; 4] {
    let w = if w == 0 { FREE_W } else { w };
    [boxed(w, h), boxed(w + 160, h + 40), boxed(w * 3 / 4, h), boxed(w / 2, h)]
}

/// Whether `inner` lies wholly in `outer`. An empty `inner` lies in it when
/// its origin does.
pub(crate) fn within(inner: Rect, outer: Rect) -> bool {
    let fits = |a: u32, n: u32, b: u32, m: u32| a >= b && a + n <= b + m;
    fits(inner.x, inner.w, outer.x, outer.w) && fits(inner.y, inner.h, outer.y, outer.h)
}
