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

//! Where a checkbox's box, tick and label sit, which draw and hit share.

use super::Checkbox;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CHECK, CHECK_RADIUS, TICK};
use crate::widgets::marked::{place, size, Marked};
use crate::widgets::rect::share;

/// The tick's start, corner and end, on a grid `CHECK` wide over the box.
pub(crate) const PATH: [(u32, u32); 3] = [(5, 10), (8, 13), (15, 6)];

/// The placed parts of a checkbox, in drawing pixels. `tick` is the path
/// in the box and `stroke` the radius of the dots it is drawn with.
pub(super) struct Parts {
    pub(super) at: Marked,
    pub(super) radius: u32,
    pub(super) tick: [(u32, u32); 3],
    pub(super) stroke: u32,
}

impl Checkbox<'_> {
    /// The box's side, then the gap and the label's width when there is a
    /// label, by the taller of the box and the label's line.
    pub fn size(&self) -> (u32, u32) {
        size(self.label)
    }

    /// The box and label as `marked::place` lays them out, the box rounded
    /// at `CHECK_RADIUS`, and the tick's path scaled to the box.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let at = place(self.label, at);
        let (m, side) = (at.mark, at.mark.w);
        let tick = PATH.map(|(x, y)| {
            (m.x.saturating_add(share(x, side, CHECK)), m.y.saturating_add(share(y, side, CHECK)))
        });
        let stroke = (share(TICK, side, CHECK) / 2).max(1);
        Parts { at, radius: scale().px(CHECK_RADIUS), tick, stroke }
    }
}
