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

//! The columns across a row: the text lane, the trailing box and the chevron
//! square.

use super::Row;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::{CHEVRON, SPACE};
use crate::widgets::rect::{centre, inset, split_left};

impl Row<'_> {
    /// The box `trailing` keeps free, the row's full height, where the app
    /// draws its control. Zero wide when the row has no trailing box.
    pub fn trailing_rect(&self, at: Rect) -> Rect {
        self.parts(at).trailing
    }

    /// The text lane, the trailing box and the chevron square, left to right,
    /// a gap apart and the row's full height. The row is padded by `SPACE.lg`,
    /// as a card pads its title, so rows drawn at a card's full width line up
    /// with its head. The trailing box is clamped to the room the chevron leaves.
    pub(super) fn lanes(&self, at: Rect) -> (Rect, Rect, Rect) {
        let s = scale();
        let (pad, gap) = (s.px(u32::from(SPACE.lg)), s.px(u32::from(SPACE.sm)));
        let inner = Rect { y: at.y, h: at.h, ..inset(at, pad) };
        let side = if self.chevron { s.px(CHEVRON) } else { 0 };
        let (rest, mark) = split_left(inner, inner.w.saturating_sub(side));
        let room = if self.chevron { rest.w.saturating_sub(gap) } else { rest.w };
        let tw = self.trailing.min(room);
        let lane = if tw > 0 { room.saturating_sub(tw).saturating_sub(gap) } else { room };
        let trailing = Rect { x: rest.x.saturating_add(room - tw), w: tw, ..rest };
        (Rect { w: lane, ..rest }, trailing, centre(mark, side, side))
    }
}
