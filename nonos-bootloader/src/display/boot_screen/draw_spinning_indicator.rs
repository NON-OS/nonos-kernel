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

static mut SPIN_FRAME: u16 = 0;

pub fn draw_spinning_indicator(x: u32, y: u32) {
    unsafe { SPIN_FRAME = (SPIN_FRAME + 1) % 360; }

    let primary_color = RGB { r: 0x00, g: 0xBC, b: 0xD4 };
    let radius = 12;

    for i in 0..8 {
        let angle = (unsafe { SPIN_FRAME } + i * 45) % 360;
        let alpha = 255 - (i * 30);
        let dot_x = x + ((angle as f32 * 3.14159 / 180.0).cos() * radius as f32) as u32;
        let dot_y = y + ((angle as f32 * 3.14159 / 180.0).sin() * radius as f32) as u32;

        let color = RGB {
            r: (primary_color.r as u16 * alpha / 255) as u8,
            g: (primary_color.g as u16 * alpha / 255) as u8,
            b: (primary_color.b as u16 * alpha / 255) as u8,
        };

        draw_filled_rect(dot_x, dot_y, 4, 4, color);
    }
}