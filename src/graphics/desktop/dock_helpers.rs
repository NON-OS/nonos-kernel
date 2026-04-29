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

use crate::graphics::framebuffer::{fill_rect, put_pixel};

/// Draw a small circle for window control buttons
pub(super) fn draw_circle_small(cx: u32, cy: u32, r: u32, color: u32) {
    let r2 = (r + 1) * (r + 1);
    for dy in 0..=(r * 2 + 1) {
        for dx in 0..=(r * 2 + 1) {
            let rx = dx as i32 - (r as i32 + 1);
            let ry = dy as i32 - (r as i32 + 1);
            if (rx * rx + ry * ry) as u32 <= r2 {
                put_pixel(cx + dx - r - 1, cy + dy - r - 1, color);
            }
        }
    }
}

pub(super) fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - r * 2, h, color);
    fill_rect(x, y + r, w, h - r * 2, color);

    for corner in 0..4u32 {
        for dy in 0..r {
            for dx in 0..r {
                let (rel_x, rel_y) = match corner {
                    0 => (r - 1 - dx, r - 1 - dy),
                    1 => (dx, r - 1 - dy),
                    2 => (r - 1 - dx, dy),
                    _ => (dx, dy),
                };
                let dist_sq = rel_x * rel_x + rel_y * rel_y;
                if dist_sq <= (r - 1) * (r - 1) {
                    let px = match corner {
                        0 | 2 => x + dx,
                        _ => x + w - r + dx,
                    };
                    let py = match corner {
                        0 | 1 => y + dy,
                        _ => y + h - r + dy,
                    };
                    put_pixel(px, py, color);
                }
            }
        }
    }
}

pub(super) fn draw_icon_plate(x: u32, y: u32, size: u32, color: u32) {
    let r = 12u32;

    for shadow in 0..3u32 {
        let alpha = 20 - shadow * 6;
        draw_rounded_rect(x + 1, y + shadow + 2, size, size, r, (alpha << 24) | 0x000000);
    }

    draw_rounded_rect(x, y, size, size, r, color);

    fill_rect(x + r, y + 1, size - r * 2, 1, 0x18FFFFFF);
    fill_rect(x + r, y + size - 1, size - r * 2, 1, 0x10000000);
}
