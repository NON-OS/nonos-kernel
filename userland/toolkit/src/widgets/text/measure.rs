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

//! Width and vertical placement of one line of body text.

use crate::font::ttf::line_height;
use crate::paint::measure_ttf;

/// The advance width of `s` at `px` in the body face, clamped at zero. It
/// measures with the same function the painter draws with.
pub fn width(s: &str, px: f32) -> u32 {
    measure_ttf(s, px).max(0) as u32
}

/// The top y that centres one line box of body text at `px` in the box
/// starting at `box_y` and `box_h` tall. `draw::text` takes the top of the
/// line box, so a row that wants its text optically centred asks here. The
/// painter and the hit test must both use it, which is what keeps a click on
/// the same pixels the label was drawn on.
pub fn centre_top(box_y: u32, box_h: u32, px: f32) -> i32 {
    let lh = line_height(px).max(1) as u32;
    let y = i32::try_from(box_y).unwrap_or(i32::MAX);
    let offset = i32::try_from(box_h.saturating_sub(lh) / 2).unwrap_or(i32::MAX);
    y.saturating_add(offset)
}
