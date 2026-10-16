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

//! Measuring and painting a label, both from one geometry helper.

use super::{Align, Label};
use crate::decorations::Rect;
use crate::design::scale::scale;
use crate::font::ttf::line_height;
use crate::paint::PaintBuffer;
use crate::theme::roles;
use crate::widgets::text;

impl Label<'_> {
    /// The width of the whole text and the line height, in drawing pixels.
    pub fn size(&self) -> (u32, u32) {
        let (px, lh) = self.metrics();
        (text::width(self.text, px), lh)
    }

    /// Paints the text on one line inside `at`, cut with an ellipsis to fit.
    pub fn draw(&self, fb: &mut PaintBuffer, at: Rect) {
        let (px, _) = self.metrics();
        let r = roles();
        let ink = if self.state.disabled { r.disabled } else { self.ink.colour(&r) };
        let s = text::truncate(self.text, at.w, px);
        let top = text::centre_top(at.y, at.h, px);
        match self.align {
            Align::Left => {
                text::left(fb, at.x, top, &s, ink, px);
            }
            Align::Centre => {
                text::centre(fb, at, top, &s, ink, px);
            }
            Align::Right => {
                text::right(fb, at.x.saturating_add(at.w), top, &s, ink, px);
            }
        }
    }

    /// The scaled text size and its line height, which size and draw share.
    fn metrics(&self) -> (f32, u32) {
        let px = scale().font(self.role.px());
        (px, line_height(px).max(0) as u32)
    }
}
