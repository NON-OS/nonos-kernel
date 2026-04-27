// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use crate::graphics::framebuffer::{fill_rect, put_pixel};

pub(super) fn draw_rounded_pill(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = h / 2;
    fill_rect(x + r, y, w - 2 * r, h, color);
    for dy in 0..h {
        for dx in 0..r {
            let rel_x = dx as i32 - r as i32 + 1;
            let rel_y = dy as i32 - r as i32;
            if rel_x * rel_x + rel_y * rel_y <= (r * r) as i32 {
                put_pixel(x + dx, y + dy, color);
                put_pixel(x + w - r + dx, y + dy, color);
            }
        }
    }
}

pub(super) fn draw_bullet(x: u32, y: u32, color: u32) {
    for dy in 0..6u32 {
        for dx in 0..6u32 {
            let rel_x = dx as i32 - 2;
            let rel_y = dy as i32 - 2;
            if rel_x * rel_x + rel_y * rel_y <= 5 {
                put_pixel(x + dx, y + dy, color);
            }
        }
    }
}

pub(super) fn isqrt(n: u32) -> u32 {
    if n == 0 {
        return 0;
    }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}
