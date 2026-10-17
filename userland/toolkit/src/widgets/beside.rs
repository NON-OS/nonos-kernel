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

//! Where a widget that opens by an anchor goes, inside the bounds it may
//! use. `Tooltip` and `Menu` both place themselves through it.

use crate::decorations::Rect;

/// The rect a widget of `size` takes by `anchor`, its size cut to `bounds`.
/// It opens `gap` below the anchor when `below`, else `gap` above it, and
/// takes the other side when that one leaves `bounds`. When neither side
/// fits it stays as near the preferred side as `bounds` allows, over the
/// anchor. Across, it starts where `left` puts it for its cut width, then
/// shifts to stay in `bounds`. All rects are in drawing pixels.
pub(crate) fn beside(
    anchor: Rect,
    bounds: Rect,
    size: (u32, u32),
    gap: u32,
    below: bool,
    left: impl FnOnce(u32) -> i64,
) -> Rect {
    let (w, h) = (size.0.min(bounds.w), size.1.min(bounds.h));
    let (ay, ah, gap) = (i64::from(anchor.y), i64::from(anchor.h), i64::from(gap));
    let above = ay - gap - i64::from(h);
    let under = ay + ah + gap;
    let (first, second) = if below { (under, above) } else { (above, under) };
    let fits = |y: i64| y == fit(y, bounds.y, bounds.h, h);
    let y = if fits(first) || !fits(second) { first } else { second };
    let (x, y) = (fit(left(w), bounds.x, bounds.w, w), fit(y, bounds.y, bounds.h, h));
    let px = |v: i64| u32::try_from(v).unwrap_or(u32::MAX);
    Rect { x: px(x), y: px(y), w, h }
}

/// `v` moved into the span from `lo` that is `room` long, so that a length
/// `len` from it stays in the span. `len` is at most `room`.
fn fit(v: i64, lo: u32, room: u32, len: u32) -> i64 {
    let lo = i64::from(lo);
    v.clamp(lo, lo + i64::from(room) - i64::from(len))
}
