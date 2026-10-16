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

//! Painting and hit testing a field, both from `parts`.

use super::Field;
use crate::decorations::Rect;
use crate::theme::roles;
use crate::widgets::rect::contains;
use crate::widgets::{draw, text, Surface};

impl Field<'_> {
    /// Paints the body, any hover wash, the edge, any icon, the shown text
    /// and, while focused, the caret in `accent_text`.
    pub fn draw(&self, fb: &mut impl Surface, at: Rect) {
        let (p, look) = (self.parts(at), self.look());
        draw::round(fb, p.body, p.radius, look.fill);
        if let Some(c) = look.wash {
            draw::round(fb, p.body, p.radius, c);
        }
        draw::outline(fb, p.body, p.radius, look.edge_w, look.edge);
        if let Some((id, sq)) = self.icon.zip(p.icon) {
            draw::icon(fb, id, sq.x, sq.y, sq.w.min(sq.h), look.icon);
        }
        text::left(fb, p.text.x, p.top, &p.shown, look.ink, p.px);
        if let Some(c) = p.caret {
            draw::fill(fb, c, roles().accent_text);
        }
    }

    /// Whether the point lies on the body.
    /// `at` and the point use `draw`'s coordinates: content coordinates when
    /// drawn through `Scrolled`, so pass the pointer's y plus the scroll.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).body, x, y)
    }
}
