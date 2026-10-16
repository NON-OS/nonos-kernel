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

//! Painting and hit testing a switch, both from `parts`.

use super::Switch;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::derive::mix;
use crate::theme::{roles, Opaque};
use crate::widgets::rect::contains;
use crate::widgets::{draw, Surface};

/// `a` moved `t`/255 of the way towards `b`.
fn tint(a: Opaque, b: Opaque, t: u8) -> Opaque {
    Opaque::new(mix(a.argb(), b.argb(), t))
}

impl Switch {
    /// Paints the track, the hover wash, the border, the knob and the focus
    /// ring. Disabled draws the track and knob in disabled tints and ignores
    /// the other states.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s, st) = (self.parts(at), roles(), scale(), self.state);
        let live = !st.disabled;
        let (track, border, knob) = if !live {
            let t = tint(r.surface, r.disabled, 64);
            (t, t, r.disabled)
        } else if self.on {
            (r.accent, r.accent, r.on_accent)
        } else {
            (tint(r.surface, r.text, 30), tint(r.surface, r.text, 46), tint(r.text, r.bg, 110))
        };
        let fill = if live && st.pressed { tint(track, r.bg, 32) } else { track };
        draw::round(fb, p.track, p.radius, fill);
        if live && st.hovered {
            draw::round(fb, p.track, p.radius, r.hover_wash);
        }
        draw::outline(fb, p.track, p.radius, s.hair(), border);
        draw::dot(fb, p.knob_x, p.knob_y, p.knob_r, knob);
        if live && st.focused {
            draw::outline(fb, p.track, p.radius, s.hair().saturating_mul(2), r.focus_ring);
        }
    }

    /// Whether the point lies on the track.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).track, x, y)
    }
}
