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

//! Where a radio's ring, dot and label sit, which draw and hit share.

use super::Radio;
use crate::decorations::Rect;
use crate::design::size::{CHECK, RADIO_DOT};
use crate::widgets::marked::{place, size, Marked};
use crate::widgets::rect::share;

/// The placed parts of a radio, in drawing pixels. `dot` is the centre and
/// radius of the dot.
pub(super) struct Parts {
    pub(super) at: Marked,
    pub(super) radius: u32,
    pub(super) dot: (u32, u32, u32),
}

impl Radio<'_> {
    /// The ring's side, then the gap and the label's width when there is a
    /// label, by the taller of the ring and the label's line.
    pub fn size(&self) -> (u32, u32) {
        size(self.label)
    }

    /// The ring and label as `marked::place` lays them out, the ring a
    /// square rounded at half its side, and the dot at its centre, scaled
    /// to the ring.
    pub(super) fn parts(&self, at: Rect) -> Parts {
        let at = place(self.label, at);
        let (m, side) = (at.mark, at.mark.w);
        let (cx, cy) = (m.x.saturating_add(side / 2), m.y.saturating_add(side / 2));
        let dot = (cx, cy, share(RADIO_DOT, side, CHECK) / 2);
        Parts { at, radius: side / 2, dot }
    }
}
