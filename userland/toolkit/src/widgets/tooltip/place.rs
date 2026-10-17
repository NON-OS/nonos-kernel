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
use crate::widgets::beside::beside;

impl Tooltip<'_> {
    /// The rect to draw the tooltip at, its size clamped to `bounds`. It opens
    /// `SPACE.xs` above `anchor`, or below it after `.below()`, and takes the
    /// other side when that one leaves `bounds`. When neither side fits it
    /// stays as near the preferred side as `bounds` allows, over the anchor.
    /// Across, it is centred on the anchor, then shifted to stay in `bounds`.
    /// All three rects are in drawing pixels.
    pub fn place(&self, anchor: Rect, bounds: Rect) -> Rect {
        let gap = scale().px(u32::from(SPACE.xs));
        let mid = |w: u32| i64::from(anchor.x) + i64::from(anchor.w / 2) - i64::from(w / 2);
        beside(anchor, bounds, self.size(), gap, self.below, mid)
    }
}
