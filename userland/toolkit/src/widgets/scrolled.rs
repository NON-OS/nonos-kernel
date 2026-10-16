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

//! Content drawn scrolled: each primitive moves up by the scroll offset and is
//! cut to the buffer's height, so a rounded rect cut by an edge reads square.

use super::surface::Surface;
use crate::paint::PaintBuffer;

/// A `PaintBuffer` seen through a vertical scroll offset. Every y is a
/// content y; its screen y is that minus `scroll`.
pub struct Scrolled<'s, 'b> {
    fb: &'s mut PaintBuffer<'b>,
    scroll: u32,
}

impl<'s, 'b> Scrolled<'s, 'b> {
    /// Paints into `fb` with the content scrolled up by `scroll` pixels.
    pub fn new(fb: &'s mut PaintBuffer<'b>, scroll: u32) -> Self {
        Scrolled { fb, scroll }
    }

    /// The screen top and height of content rows `y` to `y + h` cut to the
    /// buffer, or None when none of them is on screen.
    fn visible(&self, y: u32, h: u32) -> Option<(u32, u32)> {
        let top = i64::from(y) - i64::from(self.scroll);
        let bottom = (top + i64::from(h)).min(i64::from(self.fb.height));
        let top = top.max(0);
        (bottom > top).then(|| (top as u32, (bottom - top) as u32))
    }
}

impl Surface for Scrolled<'_, '_> {
    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, h) else { return };
        self.fb.fill_rect(x, y, w, h, argb);
    }

    fn blend_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, h) else { return };
        self.fb.blend_rect(x, y, w, h, argb);
    }

    fn fill_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, h) else { return };
        self.fb.fill_round(x, y, w, h, r.min(h / 2), argb);
    }

    fn stroke_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, t: u32, argb: u32) {
        let Some((y, h)) = self.visible(y, h) else { return };
        self.fb.stroke_round(x, y, w, h, r.min(h / 2), t, argb);
    }

    fn circle(&mut self, cx: u32, cy: u32, r: u32, argb: u32) {
        let d = r.saturating_mul(2);
        self.fill_round(cx.saturating_sub(r), cy.saturating_sub(r), d, d, r, argb);
    }

    fn text_ttf(&mut self, x: i32, top_y: i32, text: &str, argb: u32, px: f32) -> i32 {
        self.fb.text_ttf(x, top_y.saturating_sub_unsigned(self.scroll), text, argb, px)
    }
}
