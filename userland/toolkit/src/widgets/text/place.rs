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

//! Painting one line of body text aligned left, right or centred.

use super::measure::width;
use crate::decorations::Rect;
use crate::theme::Opaque;
use crate::widgets::draw;
use crate::widgets::surface::Surface;

/// Draws `s` with its left edge at `x` and `top` the top of the line box.
/// Returns the pen x after the last glyph, so runs can be chained.
pub fn left(fb: &mut impl Surface, x: u32, top: i32, s: &str, ink: Opaque, px: f32) -> i32 {
    draw::text(fb, i32::try_from(x).unwrap_or(i32::MAX), top, s, ink, px)
}

/// Draws `s` so its measured width ends at `right_x`, with `top` the top of
/// the line box. Returns the x it drew at, clamped at zero.
pub fn right(fb: &mut impl Surface, right_x: u32, top: i32, s: &str, ink: Opaque, px: f32) -> u32 {
    let x = right_x.saturating_sub(width(s, px));
    draw::text(fb, i32::try_from(x).unwrap_or(i32::MAX), top, s, ink, px);
    x
}

/// Draws `s` centred horizontally in `area`, with `top` the top of the line
/// box. A run wider than `area` starts at its left edge. Returns the x it drew
/// at.
pub fn centre(fb: &mut impl Surface, area: Rect, top: i32, s: &str, ink: Opaque, px: f32) -> u32 {
    let w = width(s, px).min(area.w);
    let x = area.x.saturating_add((area.w - w) / 2);
    draw::text(fb, i32::try_from(x).unwrap_or(i32::MAX), top, s, ink, px);
    x
}
