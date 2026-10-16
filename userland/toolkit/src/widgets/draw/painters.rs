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

//! The painters, each over one `Surface` primitive.

use super::Paint;
use crate::decorations::Rect;
use crate::icons::IconId;
use crate::theme::Opaque;
use crate::widgets::surface::Surface;

/// Writes `c` over `at` without blending. Opaque only, since the raw path
/// would copy any alpha straight into the buffer.
pub fn fill(fb: &mut impl Surface, at: Rect, c: Opaque) {
    Surface::fill_rect(fb, at.x, at.y, at.w, at.h, c.argb());
}

/// Blends `c` over `at`.
pub fn blend<C: Paint>(fb: &mut impl Surface, at: Rect, c: C) {
    Surface::blend_rect(fb, at.x, at.y, at.w, at.h, c.argb());
}

/// Blends a filled rounded rect with corner `radius`.
pub fn round<C: Paint>(fb: &mut impl Surface, at: Rect, radius: u32, c: C) {
    Surface::fill_round(fb, at.x, at.y, at.w, at.h, radius, c.argb());
}

/// Blends a rounded outline `width` thick with corner `radius`.
pub fn outline<C: Paint>(fb: &mut impl Surface, at: Rect, radius: u32, width: u32, c: C) {
    Surface::stroke_round(fb, at.x, at.y, at.w, at.h, radius, width, c.argb());
}

/// Blends a filled circle of radius `r` centred on `cx`, `cy`.
pub fn dot<C: Paint>(fb: &mut impl Surface, cx: u32, cy: u32, r: u32, c: C) {
    Surface::circle(fb, cx, cy, r, c.argb());
}

/// Draws `s` in the body face at `px`, with `top` the top of the line box.
/// Returns the pen x after the last glyph, so runs can be chained.
pub fn text(fb: &mut impl Surface, x: i32, top: i32, s: &str, ink: Opaque, px: f32) -> i32 {
    Surface::text_ttf(fb, x, top, s, ink.argb(), px)
}

/// Blends icon `id` as a `size` square at `x`, `y` in `ink`. Through
/// `Scrolled`, an icon not wholly on screen is skipped.
pub fn icon(fb: &mut impl Surface, id: IconId, x: u32, y: u32, size: u32, ink: Opaque) {
    Surface::icon(fb, id, x, y, size, ink.argb());
}
