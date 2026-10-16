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

//! A hairline between rows or groups. A separator is not clickable, so it
//! has no hit test.

use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::paint::PaintBuffer;
use crate::theme::roles;
use crate::widgets::draw;
use crate::widgets::rect::centre;

/// A hairline across its box. It is not clickable, so it has no hit test.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Separator {
    soft: bool,
}

impl Separator {
    /// A hairline in the border colour.
    pub fn new() -> Self {
        Separator { soft: false }
    }

    /// Draws in the softer border colour, for lines inside a card.
    pub fn soft(mut self) -> Self {
        self.soft = true;
        self
    }

    /// No width of its own and one hairline tall: a separator spans the
    /// width it is given.
    pub fn size(&self) -> (u32, u32) {
        (0, scale().hair())
    }

    /// Blends a hairline across `at`, centred down it.
    pub fn draw(&self, fb: &mut PaintBuffer, at: Rect) {
        let r = roles();
        let line = self.line(at);
        if self.soft {
            draw::blend(fb, line, r.border_soft);
        } else {
            draw::blend(fb, line, r.border);
        }
    }

    /// The hairline's rect: the full width of `at`, in its vertical middle.
    fn line(&self, at: Rect) -> Rect {
        centre(at, at.w, scale().hair())
    }
}
