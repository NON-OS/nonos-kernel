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

//! Painting and hit testing a row, both from `parts`.

use super::{chevron, Row};
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::design::size::CONTROL_RADIUS;
use crate::theme::derive::mix;
use crate::theme::{roles, Opaque};
use crate::widgets::rect::{contains, inset};
use crate::widgets::{draw, text, Surface};

impl Row<'_> {
    /// Paints the state washes, the label and note, the value, the chevron
    /// and the focus ring. Disabled draws every ink in `disabled` and ignores
    /// the other states.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s, st) = (self.parts(at), roles(), scale(), self.state);
        let live = !st.disabled;
        if live && st.pressed {
            draw::fill(fb, p.body, Opaque::new(mix(r.surface.argb(), r.bg.argb(), 32)));
        }
        if live && st.selected {
            draw::blend(fb, p.body, r.accent_wash);
        }
        if live && st.hovered {
            draw::blend(fb, p.body, r.hover_wash);
        }
        let ink = |c: Opaque| if live { c } else { r.disabled };
        let label = text::truncate(self.label, p.label.w, p.px);
        text::left(fb, p.label.x, p.label_top, &label, ink(r.text), p.px);
        if let Some(note) = self.note {
            let line = text::truncate(note, p.label.w, p.px);
            text::left(fb, p.label.x, p.note_top, &line, ink(r.muted), p.px);
        }
        if let Some(value) = self.value {
            let line = text::truncate(value, p.value.w, p.px);
            let right = p.value.x.saturating_add(p.value.w);
            text::right(fb, right, p.value_top, &line, ink(self.value_ink.colour(&r)), p.px);
        }
        if self.chevron {
            chevron::paint(fb, p.chevron, ink(r.muted));
        }
        if live && st.focused {
            let (hair, radius) = (s.hair(), s.px(CONTROL_RADIUS));
            draw::outline(fb, inset(p.body, hair), radius, hair.saturating_mul(2), r.focus_ring);
        }
    }

    /// Whether the point lies on the row.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).body, x, y)
    }
}
