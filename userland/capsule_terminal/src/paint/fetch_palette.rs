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

//! The row of colour swatches under the splash.

use nonos_app_skeleton::PaintBuffer;
use nonos_toolkit::theme::derive::opaque;

/// One swatch per colour, left to right. The screen's palette carries no
/// alpha, so each is made opaque before it is filled.
pub fn draw_palette(fb: &mut PaintBuffer, x: u32, y: u32, colors: &[u32]) {
    for (i, c) in colors.iter().enumerate() {
        fb.fill_rect(x + i as u32 * 18, y, 14, 10, opaque(*c));
    }
}
