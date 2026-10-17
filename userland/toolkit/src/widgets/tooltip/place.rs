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

//! Where a tooltip goes beside its anchor, inside the bounds it may use.

use super::Tooltip;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::SPACE;

impl Tooltip<'_> {
    /// The rect to draw the tooltip at, its size clamped to `bounds`. It opens
    /// `SPACE.xs` above `anchor`, or below it after `.below()`, and takes the
    /// other side when that one leaves `bounds`. When neither side fits it
    /// stays as near the preferred side as `bounds` allows, over the anchor.
    /// Across, it is centred on the anchor, then shifted to stay in `bounds`.
    /// All three rects are in drawing pixels.
    pub fn place(&self, anchor: Rect, bounds: Rect) -> Rect {
        let (w, h) = self.size();
        let (w, h) = (w.min(bounds.w), h.min(bounds.h));
        let gap = i64::from(scale().px(u32::from(SPACE.xs)));
        let (ay, ah) = (i64::from(anchor.y), i64::from(anchor.h));
        let above = ay - gap - i64::from(h);
        let below = ay + ah + gap;
        let (first, second) = if self.below { (below, above) } else { (above, below) };
        let fits = |y: i64| y == fit(y, bounds.y, bounds.h, h);
        let y = if fits(first) || !fits(second) { first } else { second };
        let mid = i64::from(anchor.x) + i64::from(anchor.w / 2) - i64::from(w / 2);
        let (x, y) = (fit(mid, bounds.x, bounds.w, w), fit(y, bounds.y, bounds.h, h));
        let px = |v: i64| u32::try_from(v).unwrap_or(u32::MAX);
        Rect { x: px(x), y: px(y), w, h }
    }
}

/// `v` moved into the span from `lo` that is `room` long, so that a length
/// `len` from it stays in the span. `len` is at most `room`.
fn fit(v: i64, lo: u32, room: u32, len: u32) -> i64 {
    let lo = i64::from(lo);
    v.clamp(lo, lo + i64::from(room) - i64::from(len))
}
