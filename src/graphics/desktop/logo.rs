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
use super::constants::{MENU_BAR_HEIGHT, DOCK_HEIGHT, SIDEBAR_WIDTH};

/*
 * official NONOS brand colors from nonos.systems/brand-guidelines
 * primary: #66FFFF (vibrant teal - innovation)
 * secondary: #2E5C5C (dark teal - stability/credibility)
 */
pub const COLOR_PRIMARY: u32 = 0xFF66FFFF;
pub const COLOR_SECONDARY: u32 = 0xFF2E5C5C;
const COLOR_LOGO_STROKE: u32 = 0xFF0A1420;

pub(super) fn draw(w: u32, h: u32) {
    let logo_size = 120u32;
    let cx = SIDEBAR_WIDTH + ((w - SIDEBAR_WIDTH) / 2);
    let cy = MENU_BAR_HEIGHT + ((h - MENU_BAR_HEIGHT - DOCK_HEIGHT) / 2);
    let logo_x = cx - logo_size / 2;
    let logo_y = cy - logo_size / 2 - 30;

    /* glow effect behind logo */
    for r in (0..40).rev() {
        let alpha = ((40 - r) * 3) as u32;
        let glow_color = (alpha << 24) | (0x66FFFF & 0xFFFFFF);
        fill_rounded_rect(
            logo_x.saturating_sub(r / 2),
            logo_y.saturating_sub(r / 2),
            logo_size + r,
            logo_size + r,
            24 + r / 3,
            glow_color,
        );
    }

    /* main logo background with gradient effect */
    fill_rounded_rect_gradient(logo_x, logo_y, logo_size, logo_size, 22, COLOR_PRIMARY, COLOR_SECONDARY);

    /* inner shadow for depth */
    for i in 0..4u32 {
        let alpha = (20 - i * 5) as u32;
        let shadow = (alpha << 24) | 0x000000;
        draw_rounded_rect_border(logo_x + i, logo_y + i, logo_size - i * 2, logo_size - i * 2, 22 - i, shadow);
    }

    /* NONOS symbol - stylized Ø (circle with diagonal slash) */
    let symbol_x = logo_x + logo_size / 2;
    let symbol_y = logo_y + logo_size / 2;
    let outer_r = 36u32;
    let inner_r = 28u32;

    /* draw the O ring */
    for dy in 0..=outer_r {
        for dx in 0..=outer_r {
            let dist_sq = dx * dx + dy * dy;
            if dist_sq <= outer_r * outer_r && dist_sq >= inner_r * inner_r {
                let shade = ((dy * 30) / outer_r).min(30) as u8;
                let color = blend_logo_colors(COLOR_LOGO_STROKE, 0xFF1A2A30, shade);
                put_pixel(symbol_x + dx, symbol_y + dy, color);
                if dx > 0 { put_pixel(symbol_x - dx, symbol_y + dy, color); }
                if dy > 0 { put_pixel(symbol_x + dx, symbol_y - dy, color); }
                if dx > 0 && dy > 0 { put_pixel(symbol_x - dx, symbol_y - dy, color); }
            }
        }
    }

    /* draw the diagonal slash through the O */
    let stroke_w = 9u32;
    let half_stroke = stroke_w / 2;
    for i in 0..(outer_r * 2 + stroke_w) {
        let base_x = symbol_x as i32 - outer_r as i32 - half_stroke as i32 + i as i32;
        let base_y = symbol_y as i32 + outer_r as i32 + half_stroke as i32 - i as i32;

        for w in 0..stroke_w {
            let px = base_x + (w as i32 - half_stroke as i32) / 2;
            let py = base_y + (w as i32 - half_stroke as i32) / 2;

            let dx = (px - symbol_x as i32).unsigned_abs();
            let dy = (py - symbol_y as i32).unsigned_abs();
            let dist_sq = dx * dx + dy * dy;

            if dist_sq <= outer_r * outer_r {
                if px >= logo_x as i32 && px < (logo_x + logo_size) as i32 &&
                   py >= logo_y as i32 && py < (logo_y + logo_size) as i32 {
                    let shade = ((py - logo_y as i32).unsigned_abs() * 20 / logo_size).min(20) as u8;
                    let color = blend_logo_colors(COLOR_LOGO_STROKE, 0xFF1A2A30, shade);
                    put_pixel(px as u32, py as u32, color);
                }
            }
        }
    }

    /* highlight on top edge of logo */
    for x in (logo_x + 22)..(logo_x + logo_size - 22) {
        let dist_from_center = ((x as i32 - cx as i32).abs() as u32 * 255) / (logo_size / 2);
        let alpha = (80u32.saturating_sub(dist_from_center / 4)).min(60);
        put_pixel(x, logo_y + 2, (alpha << 24) | 0xFFFFFF);
        put_pixel(x, logo_y + 3, ((alpha / 2) << 24) | 0xFFFFFF);
    }
}

fn fill_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    if w < r * 2 || h < r * 2 { return; }
    fill_rect(x + r, y, w - r * 2, h, color);
    fill_rect(x, y + r, r, h - r * 2, color);
    fill_rect(x + w - r, y + r, r, h - r * 2, color);

    for dy in 0..r {
        for dx in 0..r {
            let dist_sq = (r - 1 - dx) * (r - 1 - dx) + (r - 1 - dy) * (r - 1 - dy);
            if dist_sq <= (r - 1) * (r - 1) {
                put_pixel(x + dx, y + dy, color);
                put_pixel(x + w - r + dx, y + dy, color);
                put_pixel(x + dx, y + h - r + dy, color);
                put_pixel(x + w - r + dx, y + h - r + dy, color);
            }
        }
    }
}

fn fill_rounded_rect_gradient(x: u32, y: u32, w: u32, h: u32, r: u32, top_color: u32, bottom_color: u32) {
    if w < r * 2 || h < r * 2 { return; }

    for row in 0..h {
        let t = ((row * 255) / h) as u8;
        let color = blend_logo_colors(top_color, bottom_color, t);

        if row < r {
            for dx in r..w - r {
                put_pixel(x + dx, y + row, color);
            }
        } else if row >= h - r {
            for dx in r..w - r {
                put_pixel(x + dx, y + row, color);
            }
        } else {
            fill_rect(x, y + row, w, 1, color);
        }
    }

    /* corners */
    for dy in 0..r {
        for dx in 0..r {
            let dist_sq = (r - 1 - dx) * (r - 1 - dx) + (r - 1 - dy) * (r - 1 - dy);
            if dist_sq <= (r - 1) * (r - 1) {
                let t_top = ((dy * 255) / h) as u8;
                let t_bot = (((h - r + dy) * 255) / h) as u8;
                let color_top = blend_logo_colors(top_color, bottom_color, t_top);
                let color_bot = blend_logo_colors(top_color, bottom_color, t_bot);

                put_pixel(x + dx, y + dy, color_top);
                put_pixel(x + w - r + dx, y + dy, color_top);
                put_pixel(x + dx, y + h - r + dy, color_bot);
                put_pixel(x + w - r + dx, y + h - r + dy, color_bot);
            }
        }
    }
}

fn draw_rounded_rect_border(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
    if w < r * 2 || h < r * 2 { return; }

    /* top and bottom edges */
    for dx in r..w - r {
        put_pixel(x + dx, y, color);
        put_pixel(x + dx, y + h - 1, color);
    }

    /* left and right edges */
    for dy in r..h - r {
        put_pixel(x, y + dy, color);
        put_pixel(x + w - 1, y + dy, color);
    }

    /* corners */
    for angle in 0..90u32 {
        let rad_x = ((angle as f32 * 3.14159 / 180.0).cos() * (r - 1) as f32) as i32;
        let rad_y = ((angle as f32 * 3.14159 / 180.0).sin() * (r - 1) as f32) as i32;

        put_pixel((x + r - 1) as u32 - rad_x as u32, (y + r - 1) as u32 - rad_y as u32, color);
        put_pixel((x + w - r) as u32 + rad_x as u32, (y + r - 1) as u32 - rad_y as u32, color);
        put_pixel((x + r - 1) as u32 - rad_x as u32, (y + h - r) as u32 + rad_y as u32, color);
        put_pixel((x + w - r) as u32 + rad_x as u32, (y + h - r) as u32 + rad_y as u32, color);
    }
}

fn blend_logo_colors(c1: u32, c2: u32, t: u8) -> u32 {
    let r1 = ((c1 >> 16) & 0xFF) as u32;
    let g1 = ((c1 >> 8) & 0xFF) as u32;
    let b1 = (c1 & 0xFF) as u32;

    let r2 = ((c2 >> 16) & 0xFF) as u32;
    let g2 = ((c2 >> 8) & 0xFF) as u32;
    let b2 = (c2 & 0xFF) as u32;

    let t32 = t as u32;
    let inv_t = 255 - t32;

    let r = (r1 * inv_t + r2 * t32) / 255;
    let g = (g1 * inv_t + g2 * t32) / 255;
    let b = (b1 * inv_t + b2 * t32) / 255;

    0xFF000000 | (r << 16) | (g << 8) | b
}
