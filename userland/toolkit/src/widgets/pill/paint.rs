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

//! Painting and hit testing a pill, both from `parts`.

use super::Pill;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::roles;
use crate::widgets::rect::contains;
use crate::widgets::{draw, text, Surface, Tone};

impl Pill<'_> {
    /// Paints the `raised` body, its outline, the dot, the label and the
    /// focus ring. Selected adds `accent_wash` over the body and outlines in
    /// `accent_edge`, else the outline is `border_strong`; hovered adds
    /// `hover_wash`; pressed moves the body away from the label. Disabled draws
    /// the outline, dot and label in `disabled` and ignores the other states.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s, st) = (self.parts(at), roles(), scale(), self.state);
        let live = !st.disabled;
        let fill = if live && st.pressed { draw::pressed(r.raised, r.text) } else { r.raised };
        draw::round(fb, p.body, p.radius, fill);
        if live && st.selected {
            draw::round(fb, p.body, p.radius, r.accent_wash);
        }
        if live && st.hovered {
            draw::round(fb, p.body, p.radius, r.hover_wash);
        }
        if live && st.selected {
            draw::outline(fb, p.body, p.radius, s.hair(), r.accent_edge);
        } else {
            let edge = if live { r.border_strong } else { r.disabled };
            draw::outline(fb, p.body, p.radius, s.hair(), edge);
        }
        let tone = if live { self.tone.colour(&r) } else { r.disabled };
        if let Some((cx, cy, rad)) = p.dot {
            draw::dot(fb, cx, cy, rad, tone);
        }
        let ink = if live && (self.dot || self.tone == Tone::Plain) { r.text } else { tone };
        let label = text::truncate(self.label, p.label.w, p.px);
        text::left(fb, p.label.x, p.label_top, &label, ink, p.px);
        if live && st.focused {
            draw::outline(fb, p.body, p.radius, s.hair().saturating_mul(2), r.focus_ring);
        }
    }

    /// Whether the point lies on the pill's body.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).body, x, y)
    }
}
