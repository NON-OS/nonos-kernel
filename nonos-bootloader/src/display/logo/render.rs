// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::display::gop::{get_dimensions, put_pixel};

use super::bitmap::{COLOR_DARK_TEAL, COLOR_TEAL, LOGO_BITMAP, LOGO_HEIGHT, LOGO_WIDTH};

pub fn draw_logo(x: u32, y: u32, scale: u32) {
    for row in 0..LOGO_HEIGHT {
        for col in 0..LOGO_WIDTH {
            let idx = (row * LOGO_WIDTH + col) as usize;
            let pixel = LOGO_BITMAP[idx];

            let color = match pixel {
                1 => COLOR_TEAL,
                2 => COLOR_DARK_TEAL,
                _ => continue,
            };

            for sy in 0..scale {
                for sx in 0..scale {
                    put_pixel(x + col * scale + sx, y + row * scale + sy, color);
                }
            }
        }
    }
}

pub fn draw_logo_small() {
    let (width, _) = get_dimensions();
    if width == 0 {
        return;
    }

    let logo_x = width - (LOGO_WIDTH * 2) - 40;
    draw_logo(logo_x, 30, 2);
}
