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

use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, put_pixel};

pub(super) fn draw_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, r, h - 2 * r, color);
    fill_rect(x + w - r, y + r, r, h - 2 * r, color);
    draw_corner(x + r, y + r, r, color, 0);
    draw_corner(x + w - r - 1, y + r, r, color, 1);
    draw_corner(x + r, y + h - r - 1, r, color, 2);
    draw_corner(x + w - r - 1, y + h - r - 1, r, color, 3);
}

pub(super) fn draw_corner(cx: u32, cy: u32, r: u32, color: u32, quadrant: u8) {
    let r_sq = (r * r) as i32;
    for dy in 0..=r {
        for dx in 0..=r {
            let dist = (dx * dx + dy * dy) as i32;
            if dist <= r_sq {
                let (px, py) = match quadrant {
                    0 => (cx - dx, cy - dy),
                    1 => (cx + dx, cy - dy),
                    2 => (cx - dx, cy + dy),
                    _ => (cx + dx, cy + dy),
                };
                put_pixel(px, py, color);
            }
        }
    }
}

pub(super) fn draw_circle_aa(cx: u32, cy: u32, r: u32, color: u32) {
    let r_sq = (r * r) as i32;
    for dy in 0..=r {
        for dx in 0..=r {
            let dist = (dx * dx + dy * dy) as i32;
            if dist <= r_sq {
                let edge = r_sq - dist;
                let aa = if edge < (r as i32 * 3) {
                    ((edge as u32 * 255) / (r * 3)).min(255)
                } else {
                    255
                };
                let base_alpha = (color >> 24) & 0xFF;
                let final_alpha = (base_alpha * aa / 255) as u32;
                let blended = (final_alpha << 24) | (color & 0x00FFFFFF);
                put_pixel(cx + dx, cy + dy, blended);
                if dy > 0 {
                    put_pixel(cx + dx, cy - dy, blended);
                }
                if dx > 0 {
                    put_pixel(cx - dx, cy + dy, blended);
                }
                if dx > 0 && dy > 0 {
                    put_pixel(cx - dx, cy - dy, blended);
                }
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

pub fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}
