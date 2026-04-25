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

use super::primitives::{get_pixel, put_pixel};

#[inline(always)]
pub fn blend_colors(fg: u32, bg: u32) -> u32 {
    let alpha = (fg >> 24) & 0xFF;
    if alpha == 0 {
        return bg;
    }
    if alpha == 255 {
        return fg | 0xFF000000;
    }
    let inv_alpha = 255 - alpha;
    let fg_r = (fg >> 16) & 0xFF;
    let fg_g = (fg >> 8) & 0xFF;
    let fg_b = fg & 0xFF;
    let bg_r = (bg >> 16) & 0xFF;
    let bg_g = (bg >> 8) & 0xFF;
    let bg_b = bg & 0xFF;
    let r = (fg_r * alpha + bg_r * inv_alpha) / 255;
    let g = (fg_g * alpha + bg_g * inv_alpha) / 255;
    let b = (fg_b * alpha + bg_b * inv_alpha) / 255;
    0xFF000000 | (r << 16) | (g << 8) | b
}

#[inline(always)]
pub fn put_pixel_blend(x: u32, y: u32, color: u32) {
    let alpha = (color >> 24) & 0xFF;
    if alpha == 0 {
        return;
    }
    if alpha == 255 {
        put_pixel(x, y, color);
        return;
    }
    let bg = get_pixel(x, y);
    put_pixel(x, y, blend_colors(color, bg));
}

pub fn fill_rect_blend(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let alpha = (color >> 24) & 0xFF;
    if alpha == 0 {
        return;
    }
    for py in y..y + h {
        for px in x..x + w {
            put_pixel_blend(px, py, color);
        }
    }
}

pub fn rounded_rect_blend(x: u32, y: u32, w: u32, h: u32, radius: u32, color: u32) {
    if w == 0 || h == 0 {
        return;
    }
    let r = radius.min(w / 2).min(h / 2);
    if r == 0 {
        fill_rect_blend(x, y, w, h, color);
        return;
    }
    fill_rect_blend(x + r, y, w - 2 * r, h, color);
    fill_rect_blend(x, y + r, w, h - 2 * r, color);
    for py in 0..r {
        for px in 0..r {
            let dx = r - px;
            let dy = r - py;
            if dx * dx + dy * dy <= r * r {
                put_pixel_blend(x + px, y + py, color);
                put_pixel_blend(x + w - 1 - px, y + py, color);
                put_pixel_blend(x + px, y + h - 1 - py, color);
                put_pixel_blend(x + w - 1 - px, y + h - 1 - py, color);
            }
        }
    }
}
