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

//! Painting and hit testing a navigation item, both from `parts`.

use super::NavItem;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::derive::mix;
use crate::theme::{roles, Opaque};
use crate::widgets::rect::contains;
use crate::widgets::{draw, text, Surface};

impl NavItem<'_> {
    /// Paints the body, any icon, the label and the focus ring. Active fills
    /// with `accent_wash`, outlines in `accent_edge` and labels in
    /// `accent_text`. Otherwise the label is muted, pressed fills with
    /// `surface` darkened towards `bg` and hovered adds `hover_wash` over
    /// that. Disabled draws the label in `disabled` and nothing else. The
    /// icon takes the label's ink.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s, st) = (self.parts(at), roles(), scale(), self.state);
        let live = !st.disabled;
        if live && self.active {
            draw::round(fb, p.body, p.radius, r.accent_wash);
            draw::outline(fb, p.body, p.radius, s.hair(), r.accent_edge);
        }
        if live && !self.active && st.pressed {
            let held = Opaque::new(mix(r.surface.argb(), r.bg.argb(), 32));
            draw::round(fb, p.body, p.radius, held);
        }
        if live && !self.active && st.hovered {
            draw::round(fb, p.body, p.radius, r.hover_wash);
        }
        let ink = match (live, self.active) {
            (false, _) => r.disabled,
            (true, true) => r.accent_text,
            (true, false) => r.muted,
        };
        if let Some((id, sq)) = self.icon.zip(p.icon) {
            draw::icon(fb, id, sq.x, sq.y, sq.w.min(sq.h), ink);
        }
        let label = text::truncate(self.label, p.label.w, p.px);
        text::left(fb, p.label.x, p.label_top, &label, ink, p.px);
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
