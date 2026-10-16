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

//! Typed painters for widget code, so a widget cannot send an alpha colour
//! through the raw path.

use crate::decorations::Rect;
use crate::paint::PaintBuffer;
use crate::theme::{Opaque, Translucent};

/// A theme colour a blending painter accepts.
pub trait Paint: Copy {
    /// The packed ARGB value.
    fn argb(self) -> u32;
}

impl Paint for Opaque {
    fn argb(self) -> u32 {
        Opaque::argb(self)
    }
}

impl Paint for Translucent {
    fn argb(self) -> u32 {
        Translucent::argb(self)
    }
}

/// Writes `c` over `at` without blending. Opaque only, since the raw path
/// would copy any alpha straight into the buffer.
pub fn fill(fb: &mut PaintBuffer, at: Rect, c: Opaque) {
    fb.fill_rect(at.x, at.y, at.w, at.h, c.argb());
}

/// Blends `c` over `at`.
pub fn blend<C: Paint>(fb: &mut PaintBuffer, at: Rect, c: C) {
    fb.blend_rect(at.x, at.y, at.w, at.h, c.argb());
}

/// Blends a filled rounded rect with corner `radius`.
pub fn round<C: Paint>(fb: &mut PaintBuffer, at: Rect, radius: u32, c: C) {
    fb.fill_round(at.x, at.y, at.w, at.h, radius, c.argb());
}

/// Blends a rounded outline `width` thick with corner `radius`.
pub fn outline<C: Paint>(fb: &mut PaintBuffer, at: Rect, radius: u32, width: u32, c: C) {
    fb.stroke_round(at.x, at.y, at.w, at.h, radius, width, c.argb());
}

/// Blends a filled circle of radius `r` centred on `cx`, `cy`.
pub fn dot<C: Paint>(fb: &mut PaintBuffer, cx: u32, cy: u32, r: u32, c: C) {
    fb.circle(cx, cy, r, c.argb());
}

/// Draws `s` in the body face at `px`, with `top` the top of the line box.
/// Returns the pen x after the last glyph, so runs can be chained.
pub fn text(fb: &mut PaintBuffer, x: i32, top: i32, s: &str, ink: Opaque, px: f32) -> i32 {
    fb.text_ttf(x, top, s, ink.argb(), px)
}
