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

//! Painting and hit testing a checkbox, both from `parts`.

use super::Checkbox;
use crate::decorations::Rect;
use crate::widgets::marked::paint;
use crate::widgets::rect::contains;
use crate::widgets::{draw, Surface};

impl Checkbox<'_> {
    /// Paints the box, the hover wash, the outline, the tick, the label and
    /// the focus ring. On fills the box with `accent` under an `on_accent`
    /// tick; off outlines it in `border_strong` over the ground, and pressed
    /// gives it a `surface` fill moved away from the outline. Disabled
    /// outlines the box and draws the tick and label in `disabled`, and
    /// ignores the other states.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let p = self.parts(at);
        paint(fb, &p.at, p.radius, self.on, self.label, self.state, |fb, ink| {
            p.tick_dots().for_each(|(x, y)| draw::dot(fb, x, y, p.stroke, ink));
        });
    }

    /// Whether the point lies on the box or its label.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).at.body, x, y)
    }
}
