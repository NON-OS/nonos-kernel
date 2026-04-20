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

use crate::graphics::framebuffer::draw_filled_rect;
use crate::graphics::colors::RGB;

pub fn draw_gradient_background(width: u32, height: u32) {
    let top_color = RGB { r: 0x0A, g: 0x0E, b: 0x27 };
    let bottom_color = RGB { r: 0x1A, g: 0x1A, b: 0x2E };

    for y in 0..height {
        let ratio = y as f32 / height as f32;
        let color = RGB {
            r: (top_color.r as f32 + (bottom_color.r as f32 - top_color.r as f32) * ratio) as u8,
            g: (top_color.g as f32 + (bottom_color.g as f32 - top_color.g as f32) * ratio) as u8,
            b: (top_color.b as f32 + (bottom_color.b as f32 - top_color.b as f32) * ratio) as u8,
        };
        draw_filled_rect(0, y, width, 1, color);
    }
}