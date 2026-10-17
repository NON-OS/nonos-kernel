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

//! Painting and hit testing an icon button, both from `parts`.

use super::IconButton;
use crate::decorations::Rect;
use crate::widgets::rect::contains;
use crate::widgets::{draw, text, Surface};

impl IconButton<'_> {
    /// Paints the body as a `Button` of the same kind and state draws it,
    /// with its fill, hover wash, outline, press and focus ring, then the
    /// icon and any label in that button's label ink.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, button) = (self.parts(at), self.body());
        let ink = button.ink();
        button.draw(fb, p.body);
        draw::icon(fb, self.icon, p.icon.x, p.icon.y, p.icon.w.min(p.icon.h), ink);
        if !self.label.is_empty() {
            let label = text::truncate(self.label, p.label.w, p.px);
            text::left(fb, p.label.x, p.label_top, &label, ink, p.px);
        }
    }

    /// Whether the point lies on the body.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).body, x, y)
    }
}
