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

//! What a widget paints on. A `PaintBuffer` draws at its own coordinates;
//! `Scrolled` draws content scrolled by an offset.

use crate::paint::PaintBuffer;

/// The primitives the widgets paint with, in the shape `PaintBuffer` has.
pub trait Surface {
    /// Writes `argb` over the rect without blending.
    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32);

    /// Blends `argb` over the rect.
    fn blend_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32);

    /// Blends a filled rounded rect with corner radius `r`.
    fn fill_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, argb: u32);

    /// Blends a rounded outline `t` thick with corner radius `r`.
    fn stroke_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, t: u32, argb: u32);

    /// Blends a filled circle of radius `r` centred on `cx`, `cy`.
    fn circle(&mut self, cx: u32, cy: u32, r: u32, argb: u32);

    /// Draws `text` in the body face with `top_y` the top of the line box.
    /// Returns the pen x after the last glyph.
    fn text_ttf(&mut self, x: i32, top_y: i32, text: &str, argb: u32, px: f32) -> i32;
}

impl Surface for PaintBuffer<'_> {
    fn fill_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        PaintBuffer::fill_rect(self, x, y, w, h, argb);
    }

    fn blend_rect(&mut self, x: u32, y: u32, w: u32, h: u32, argb: u32) {
        PaintBuffer::blend_rect(self, x, y, w, h, argb);
    }

    fn fill_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, argb: u32) {
        PaintBuffer::fill_round(self, x, y, w, h, r, argb);
    }

    fn stroke_round(&mut self, x: u32, y: u32, w: u32, h: u32, r: u32, t: u32, argb: u32) {
        PaintBuffer::stroke_round(self, x, y, w, h, r, t, argb);
    }

    fn circle(&mut self, cx: u32, cy: u32, r: u32, argb: u32) {
        PaintBuffer::circle(self, cx, cy, r, argb);
    }

    fn text_ttf(&mut self, x: i32, top_y: i32, text: &str, argb: u32, px: f32) -> i32 {
        PaintBuffer::text_ttf(self, x, top_y, text, argb, px)
    }
}
