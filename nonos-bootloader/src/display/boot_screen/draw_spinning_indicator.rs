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

use crate::display::gop::fill_rect;
use super::math_utils::{sin_approx, cos_approx};


static mut SPIN_FRAME: u16 = 0;

pub fn draw_spinning_indicator(x: u32, y: u32) {
    unsafe { SPIN_FRAME = (SPIN_FRAME + 1) % 360; }

    let primary_color = 0xFF00BCD4u32;
    let radius = 12;

    for i in 0..8 {
        let angle = (unsafe { SPIN_FRAME } + i * 45) % 360;
        let alpha = 255 - (i * 30);
        let angle_rad = angle as f32 * 3.14159 / 180.0;
        let dot_x = (x as f32 + cos_approx(angle_rad) * radius as f32) as u32;
        let dot_y = (y as f32 + sin_approx(angle_rad) * radius as f32) as u32;

        let primary_r = (primary_color >> 16) & 0xFF;
        let primary_g = (primary_color >> 8) & 0xFF;
        let primary_b = primary_color & 0xFF;

        let r = (primary_r * alpha as u32 / 255) & 0xFF;
        let g = (primary_g * alpha as u32 / 255) & 0xFF;
        let b = (primary_b * alpha as u32 / 255) & 0xFF;

        let color = 0xFF000000 | (r << 16) | (g << 8) | b;
        fill_rect(dot_x, dot_y, 4, 4, color);
    }
}