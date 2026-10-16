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
use crate::paint::PaintBuffer;
use crate::theme::roles;
use crate::widgets::rect::contains;
use crate::widgets::{draw, text};

impl Field<'_> {
    /// Paints the body, any hover wash, the edge, the shown text and, while
    /// focused, the caret in `accent`.
    pub fn draw(&self, fb: &mut PaintBuffer, at: Rect) {
        let (p, look) = (self.parts(at), self.look());
        draw::round(fb, p.body, p.radius, look.fill);
        if let Some(c) = look.wash {
            draw::round(fb, p.body, p.radius, c);
        }
        draw::outline(fb, p.body, p.radius, look.edge_w, look.edge);
        text::left(fb, p.text.x, p.top, &p.shown, look.ink, p.px);
        if let Some(c) = p.caret {
            draw::fill(fb, c, roles().accent);
        }
    }

    /// Whether the point lies on the body.
    pub fn hit(&self, at: Rect, x: i32, y: i32) -> bool {
        contains(self.parts(at).body, x, y)
    }
}
