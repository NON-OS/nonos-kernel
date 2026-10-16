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

//! Painting a progress bar from `parts`. There is no hit test.

use super::Progress;
use crate::decorations::Rect;
use crate::paint::PaintBuffer;
use crate::theme::derive::mix;
use crate::theme::{roles, Opaque};
use crate::widgets::{draw, Tone};

impl Progress {
    /// Paints the track, then the fill in the tone's colour, or `accent`
    /// for `Plain`. Disabled fills in `disabled`.
    pub fn draw(&self, fb: &mut PaintBuffer, at: Rect) {
        let (p, r) = (self.parts(at), roles());
        let track = Opaque::new(mix(r.surface.argb(), r.text.argb(), 38));
        let ink = match (self.state.disabled, self.tone) {
            (true, _) => r.disabled,
            (false, Tone::Plain) => r.accent,
            (false, tone) => tone.colour(&r),
        };
        draw::round(fb, p.track, p.radius, track);
        draw::round(fb, p.fill, p.radius, ink);
    }
}
