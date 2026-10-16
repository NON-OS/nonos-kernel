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

//! Painting and hit testing a slider, both from `parts`.

use super::Slider;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::paint::PaintBuffer;
use crate::theme::derive::mix;
use crate::theme::{roles, Opaque};
use crate::widgets::draw;
use crate::widgets::rect::{contains, share};

impl Slider {
    /// Paints the track, the accent fill up to the knob, and the knob with
    /// its accent outline. Hover, press and focus mark the knob, the part
    /// that is dragged. Disabled draws the fill and knob in `disabled` and
    /// ignores the other states.
    pub fn draw(&self, fb: &mut PaintBuffer, at: Rect) {
        let (p, r, s, st) = (self.parts(at), roles(), scale(), self.state);
        let live = !st.disabled;
        let (radius, hair, (cx, cy)) = (p.track.h / 2, s.hair(), p.dot);
        let track = Opaque::new(mix(r.surface.argb(), r.text.argb(), 38));
        let ink = if live { r.accent } else { r.disabled };
        let face = if !live {
            r.disabled
        } else if st.pressed {
            Opaque::new(mix(r.on_accent.argb(), r.bg.argb(), 32))
        } else {
            r.on_accent
        };
        draw::round(fb, p.track, radius, track);
        draw::round(fb, p.fill, radius, ink);
        draw::dot(fb, cx, cy, p.knob_r, face);
        if live && st.hovered {
            draw::dot(fb, cx, cy, p.knob_r, r.hover_wash);
        }
        draw::outline(fb, p.knob, p.knob_r, hair, ink);
        if live && st.focused {
            draw::outline(fb, p.knob, p.knob_r, hair.saturating_mul(2), r.focus_ring);
        }
    }

    /// None outside the slider's box; inside, the value under `x`, rounded
    /// to the nearest and clamped to 0..=max, from the knob's travel.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> Option<u32> {
        let p = self.parts(at);
        if !contains(p.body, x, y) {
            return None;
        }
        let along = u32::try_from(x).unwrap_or(0).saturating_sub(p.start).min(p.travel);
        Some(share(along, self.max, p.travel))
    }
}
