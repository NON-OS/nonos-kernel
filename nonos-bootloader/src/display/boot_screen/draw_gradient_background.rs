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

pub fn draw_gradient_background(width: u32, height: u32) {
    let top_color = 0xFF0A0E27u32;
    let bottom_color = 0xFF1A1A2Eu32;

    for y in 0..height {
        let ratio = y as f32 / height as f32;
        let top_r = (top_color >> 16) & 0xFF;
        let top_g = (top_color >> 8) & 0xFF;
        let top_b = top_color & 0xFF;

        let bottom_r = (bottom_color >> 16) & 0xFF;
        let bottom_g = (bottom_color >> 8) & 0xFF;
        let bottom_b = bottom_color & 0xFF;

        let r = (top_r as f32 + (bottom_r as f32 - top_r as f32) * ratio) as u32;
        let g = (top_g as f32 + (bottom_g as f32 - top_g as f32) * ratio) as u32;
        let b = (top_b as f32 + (bottom_b as f32 - top_b as f32) * ratio) as u32;

        let color = 0xFF000000 | (r << 16) | (g << 8) | b;
        fill_rect(0, y, width, 1, color);
    }
}