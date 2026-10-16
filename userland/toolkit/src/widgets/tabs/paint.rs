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

//! Painting and hit testing a tab strip, both from `parts`.

use super::Tabs;
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::theme::roles;
use crate::widgets::rect::contains;
use crate::widgets::{draw, text, Surface};

impl Tabs<'_> {
    /// Paints each tab: the selected one on an accent wash with its label in
    /// `accent_text`, a hovered one on a hover wash, the rest with muted
    /// labels, then the focus ring round the selected tab. Disabled draws
    /// every label in `disabled` and no washes or ring.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, r, s, st) = (self.parts(at), roles(), scale(), self.state);
        let live = !st.disabled;
        for (i, (tab, label)) in p.tabs.iter().zip(self.labels).enumerate() {
            let on = i == self.selected;
            if live && on {
                draw::round(fb, tab.body, p.radius, r.accent_wash);
            } else if live && self.hovered == Some(i) {
                draw::round(fb, tab.body, p.radius, r.hover_wash);
            }
            let ink = match (live, on) {
                (false, _) => r.disabled,
                (true, true) => r.accent_text,
                (true, false) => r.muted,
            };
            let line = text::truncate(label, tab.label.w, p.px);
            text::centre(fb, tab.label, p.label_top, &line, ink, p.px);
            if live && on && st.focused {
                let width = s.hair().saturating_mul(2);
                draw::outline(fb, tab.body, p.radius, width, r.focus_ring);
            }
        }
    }

    /// The index of the tab under the point, if any.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> Option<usize> {
        self.parts(at).tabs.iter().position(|t| contains(t.body, x, y))
    }
}
