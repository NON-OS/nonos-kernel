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

//! Painting and hit testing a button, both from `parts`.

use super::Button;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::roles;
use crate::widgets::rect::contains;
use crate::widgets::{draw, text, Surface};

impl Button<'_> {
    /// Paints the body, the hover wash, the outline, the label and the focus
    /// ring. Pressed moves the fill away from the label's ink; a `Plain`
    /// button, which has no fill, gets `surface` moved the same way, so it
    /// reads as held. Disabled ignores the other states.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s, st) = (self.parts(at), roles(), scale(), self.state);
        let (live, look) = (!st.disabled, self.look());
        let fill = if live && st.pressed {
            let base = look.fill.unwrap_or(r.surface);
            Some(draw::pressed(base, look.ink))
        } else {
            look.fill
        };
        if let Some(c) = fill {
            draw::round(fb, p.body, p.radius, c);
        }
        if live && st.hovered {
            draw::round(fb, p.body, p.radius, r.hover_wash);
        }
        if let Some(c) = look.edge {
            draw::outline(fb, p.body, p.radius, s.hair(), c);
        }
        let label = text::truncate(self.label, p.label.w, p.px);
        text::centre(fb, p.label, p.label_top, &label, look.ink, p.px);
        if live && st.focused {
            draw::outline(fb, p.body, p.radius, s.hair().saturating_mul(2), r.focus_ring);
        }
    }

    /// Whether the point lies on the body.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).body, x, y)
    }
}
