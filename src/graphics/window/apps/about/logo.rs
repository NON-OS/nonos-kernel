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

use super::utils::isqrt;
use crate::graphics::framebuffer::put_pixel;

const COLOR_BRAND_SECONDARY: u32 = 0xFF2C2C2E;

pub(super) fn draw_nonos_logo(cx: u32, y: u32, size: u32) {
    let glass_cx = cx - 8;
    let glass_cy = y + size / 2 - 8;
    let outer_r = size / 2 - 6;
    let inner_r = outer_r - 7;

    draw_glow(cx, y, size, outer_r);
    draw_ring(cx, y, size, outer_r, inner_r);
    draw_handle(glass_cx, glass_cy, outer_r, size);
}

fn draw_glow(cx: u32, y: u32, size: u32, outer_r: u32) {
    for dy in 0..size {
        for dx in 0..size {
            let rel_x = dx as i32 - (size / 2) as i32 + 8;
            let rel_y = dy as i32 - (size / 2) as i32 + 8;
            let dist = isqrt((rel_x * rel_x + rel_y * rel_y) as u32);
            if dist > outer_r && dist <= outer_r + 6 {
                let alpha = ((outer_r + 6 - dist) * 40 / 6) as u32;
                put_pixel(cx - size / 2 + dx, y + dy, (alpha << 24) | 0x007AFF);
            }
        }
    }
}

fn draw_ring(cx: u32, y: u32, size: u32, outer_r: u32, inner_r: u32) {
    for dy in 0..size {
        for dx in 0..size {
            let rel_x = dx as i32 - (size / 2) as i32 + 8;
            let rel_y = dy as i32 - (size / 2) as i32 + 8;
            let dist = isqrt((rel_x * rel_x + rel_y * rel_y) as u32);
            if dist >= inner_r && dist <= outer_r {
                let t = (dy * 256 / size) as u32;
                let r = ((t * 0x40) / 256).min(0x40);
                let g = 0x7A + ((256 - t) * 0x40 / 256).min(0x85);
                let b = 0xFF - (t / 8).min(0x30);
                put_pixel(cx - size / 2 + dx, y + dy, 0xFF000000 | (r << 16) | (g << 8) | b);
            } else if dist < inner_r && dist > inner_r / 3 {
                let shade = ((inner_r - dist) * 15 / inner_r) as u32;
                if shade > 3 {
                    put_pixel(cx - size / 2 + dx, y + dy, (shade << 24) | 0x007AFF);
                }
            }
        }
    }
}

fn draw_handle(glass_cx: u32, glass_cy: u32, outer_r: u32, size: u32) {
    let start_x = glass_cx + (outer_r as i32 * 70 / 100) as u32;
    let start_y = glass_cy + (outer_r as i32 * 70 / 100) as u32;
    let len = size * 40 / 100;
    for i in 0..len {
        for t in 0..10u32 {
            let offset = t as i32 - 5;
            let px = (start_x + i) as i32 + offset / 2;
            let py = (start_y + i) as i32 - offset / 2;
            let shade = (i * 60 / len) as u32;
            let r = shade.min(0x40);
            let g = 0x7A_u32.saturating_sub(shade.min(0x30));
            let b = 0xFF_u32.saturating_sub(shade.min(0x50));
            put_pixel(px as u32, py as u32, 0xFF000000 | (r << 16) | (g << 8) | b);
        }
    }
    let cap_cx = start_x + len;
    let cap_cy = start_y + len;
    for dy in 0..12u32 {
        for dx in 0..12u32 {
            let rel_x = dx as i32 - 5;
            let rel_y = dy as i32 - 5;
            if rel_x * rel_x + rel_y * rel_y <= 25 {
                put_pixel(cap_cx - 5 + dx, cap_cy - 5 + dy, COLOR_BRAND_SECONDARY);
            }
        }
    }
}
