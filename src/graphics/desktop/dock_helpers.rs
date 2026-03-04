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

pub(super) fn draw_circle_small(cx: u32, cy: u32, r: u32, color: u32) {
    for dy in 0..r * 2 + 1 {
        for dx in 0..r * 2 + 1 {
            let rel_x = dx as i32 - r as i32;
            let rel_y = dy as i32 - r as i32;
            if rel_x * rel_x + rel_y * rel_y <= (r * r) as i32 {
                put_pixel(cx - r + dx, cy - r + dy, color);
            }
        }
    }
}

pub(super) fn isqrt(n: u32) -> u32 {
    if n == 0 { return 0; }
    let mut x = n;
    let mut y = (x + 1) / 2;
    while y < x {
        x = y;
        y = (x + n / x) / 2;
    }
    x
}

pub(super) fn atan2_approx(y: i32, x: i32) -> i32 {
    if x == 0 && y == 0 { return 0; }
    let ax = x.abs();
    let ay = y.abs();
    let angle = if ax > ay { 45 * ay / ax } else if ay > 0 { 90 - 45 * ax / ay } else { 0 };
    match (x >= 0, y >= 0) {
        (true, true) => angle,
        (false, true) => 180 - angle,
        (false, false) => 180 + angle,
        (true, false) => 360 - angle,
    }
}

pub(super) fn blend_colors(color1: u32, color2: u32, factor: u8) -> u32 {
    let f = factor as u32;
    let inv_f = 255 - f;
    let r = (((color1 >> 16) & 0xFF) * inv_f + ((color2 >> 16) & 0xFF) * f) / 255;
    let g = (((color1 >> 8) & 0xFF) * inv_f + ((color2 >> 8) & 0xFF) * f) / 255;
    let b = ((color1 & 0xFF) * inv_f + (color2 & 0xFF) * f) / 255;
    0xFF000000 | (r << 16) | (g << 8) | b
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
                    let px = match corner { 0 | 2 => x + dx, _ => x + w - r + dx };
                    let py = match corner { 0 | 1 => y + dy, _ => y + h - r + dy };
                    put_pixel(px, py, color);
                }
            }
        }
    }
}

pub(super) fn draw_icon_plate(x: u32, y: u32, size: u32, color: u32) {
    let r = 10u32;
    draw_rounded_rect(x, y, size, size, r, color);

    for px in x + r..x + size - r {
        put_pixel(px, y + 1, 0x0AFFFFFF);
    }
}
