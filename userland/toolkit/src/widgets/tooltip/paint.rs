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

//! Painting a tooltip from `parts`. A tooltip takes no pointer, so it has no
//! hit test.

use super::Tooltip;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::roles;
use crate::widgets::{draw, text, Surface};

impl Tooltip<'_> {
    /// Paints the `shadow` under the box, the opaque `raised` box over it with
    /// a `border` hairline, then the text in `text`, cut with `…` to one line.
    /// Disabled draws the text in `disabled`.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s) = (self.parts(at), roles(), scale());
        draw::round(fb, p.shadow, p.radius, r.shadow);
        draw::round(fb, p.body, p.radius, r.raised);
        draw::outline(fb, p.body, p.radius, s.hair(), r.border);
        let ink = if self.state.disabled { r.disabled } else { r.text };
        let line = text::truncate(self.text, p.room.w, p.px);
        text::left(fb, p.room.x, p.top, &line, ink, p.px);
    }
}
