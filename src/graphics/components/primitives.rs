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

use crate::graphics::design_system::shadows::Shadow;
use crate::graphics::framebuffer::{fill_rect, put_pixel};

pub fn rounded_rect(x: u32, y: u32, w: u32, h: u32, radius: u32, color: u32) {
    if w == 0 || h == 0 {
        return;
    }
    let r = radius.min(w / 2).min(h / 2);
    if r == 0 {
        fill_rect(x, y, w, h, color);
        return;
    }
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, w, h - 2 * r, color);
    for py in 0..r {
        for px in 0..r {
            let dx = r - px;
            let dy = r - py;
            if dx * dx + dy * dy <= r * r {
                put_pixel(x + px, y + py, color);
                put_pixel(x + w - 1 - px, y + py, color);
                put_pixel(x + px, y + h - 1 - py, color);
                put_pixel(x + w - 1 - px, y + h - 1 - py, color);
            }
        }
    }
}

pub fn circle(cx: u32, cy: u32, radius: u32, color: u32) {
    let r_sq = (radius * radius) as i32;
    for dy in 0..=radius {
        for dx in 0..=radius {
            if (dx * dx + dy * dy) as i32 <= r_sq {
                put_pixel(cx + dx, cy + dy, color);
                if dy > 0 {
                    put_pixel(cx + dx, cy - dy, color);
                }
                if dx > 0 {
                    put_pixel(cx - dx, cy + dy, color);
                }
                if dx > 0 && dy > 0 {
                    put_pixel(cx - dx, cy - dy, color);
                }
            }
        }
    }
}

pub fn shadow(x: u32, y: u32, w: u32, h: u32, radius: u32, s: &Shadow) {
    for layer in 0..s.layers {
        let alpha = s.base_alpha.saturating_sub(layer * s.alpha_decay);
        if alpha == 0 {
            continue;
        }
        let offset = layer as i32 + s.offset_y;
        let shadow_color = ((alpha & 0xFF) << 24) | s.color;
        let sy = if offset >= 0 { y + offset as u32 } else { y.saturating_sub((-offset) as u32) };
        rounded_rect(x + s.offset_x as u32, sy, w + s.spread * 2, h, radius, shadow_color);
    }
}

pub fn rounded_rect_outline(
    x: u32,
    y: u32,
    w: u32,
    h: u32,
    radius: u32,
    thickness: u32,
    color: u32,
) {
    for i in 0..thickness {
        let r = if radius > i { radius - i } else { 0 };
        rounded_rect_border(x + i, y + i, w - i * 2, h - i * 2, r, color);
    }
}

fn rounded_rect_border(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    if w < 2 || h < 2 {
        return;
    }
    fill_rect(x + r, y, w - 2 * r, 1, color);
    fill_rect(x + r, y + h - 1, w - 2 * r, 1, color);
    fill_rect(x, y + r, 1, h - 2 * r, color);
    fill_rect(x + w - 1, y + r, 1, h - 2 * r, color);
}
