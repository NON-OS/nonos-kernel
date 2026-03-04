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
use super::sidebar_utils::{blend_colors, isqrt};

const COLOR_GOLD: u32 = 0xFFFFB800;
const COLOR_GOLD_LIGHT: u32 = 0xFFFFD54F;
const COLOR_GOLD_DARK: u32 = 0xFFCC9200;
const COLOR_PURPLE: u32 = 0xFFBB86FC;
const COLOR_PURPLE_DARK: u32 = 0xFF9965E0;
const COLOR_BLUE: u32 = 0xFF64B5F6;
const COLOR_BLUE_LIGHT: u32 = 0xFF90CAF9;
const ICON_BG: u32 = 0xFF12161C;

pub(super) fn draw_icon_plate(cx: u32, cy: u32, size: u32) {
    let x = cx - size / 2;
    let y = cy - size / 2;
    let r = 8u32;

    fill_rect(x + r, y, size - r * 2, size, ICON_BG);
    fill_rect(x, y + r, size, size - r * 2, ICON_BG);

    for dy in 0..r {
        for dx in 0..r {
            let dist_sq = (r - 1 - dx) * (r - 1 - dx) + (r - 1 - dy) * (r - 1 - dy);
            if dist_sq <= (r - 1) * (r - 1) {
                put_pixel(x + dx, y + dy, ICON_BG);
                put_pixel(x + size - r + dx, y + dy, ICON_BG);
                put_pixel(x + dx, y + size - r + dy, ICON_BG);
                put_pixel(x + size - r + dx, y + size - r + dy, ICON_BG);
            }
        }
    }

    for px in x + r..x + size - r {
        put_pixel(px, y, 0x08FFFFFF);
    }
}

pub(super) fn draw_folder_icon(cx: u32, cy: u32) {
    draw_icon_plate(cx, cy, 40);

    let x = cx - 14;
    let y = cy - 10;

    fill_rect(x + 3, y + 5, 22, 15, COLOR_GOLD_DARK);
    fill_rect(x + 1, y + 3, 24, 17, COLOR_GOLD);
    fill_rect(x + 1, y, 10, 5, COLOR_GOLD);
    fill_rect(x + 10, y + 1, 2, 3, COLOR_GOLD);
    fill_rect(x + 11, y + 2, 2, 2, COLOR_GOLD);

    for px in 0..22u32 {
        let alpha = 40 - (px * 40 / 22);
        put_pixel(x + 2 + px, y + 4, (alpha << 24) | 0xFFFFFF);
    }

    fill_rect(x + 2, y + 7, 22, 1, COLOR_GOLD_LIGHT);

    for px in 0..20u32 {
        put_pixel(x + 3 + px, y + 18, 0x20000000);
    }
}

pub(super) fn draw_terminal_icon(cx: u32, cy: u32) {
    draw_icon_plate(cx, cy, 40);

    let x = cx - 16;
    let y = cy - 12;

    fill_rect(x + 2, y + 2, 28, 22, 0xFF0A0E14);
    fill_rect(x + 2, y + 2, 28, 5, 0xFF21262D);

    for (i, &color) in [0xFFFF5F56, 0xFFFFBD2E, 0xFF27C93F].iter().enumerate() {
        let bx = x + 5 + i as u32 * 4;
        put_pixel(bx, y + 4, color);
        put_pixel(bx + 1, y + 4, color);
    }

    fill_rect(x + 5, y + 10, 2, 2, 0xFF00E676);
    fill_rect(x + 9, y + 10, 10, 2, 0xFF6E7681);
    fill_rect(x + 5, y + 15, 2, 2, 0xFF00E676);
    fill_rect(x + 9, y + 15, 14, 2, 0xFF6E7681);
    fill_rect(x + 24, y + 15, 3, 2, 0xFFFFFFFF);
}

pub(super) fn draw_browser_icon(cx: u32, cy: u32) {
    draw_icon_plate(cx, cy, 40);

    let center_x = cx;
    let center_y = cy;
    let radius = 13u32;

    for dy in 0..radius * 2 + 2 {
        for dx in 0..radius * 2 + 2 {
            let rel_x = dx as i32 - radius as i32 - 1;
            let rel_y = dy as i32 - radius as i32 - 1;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;

            if dist_sq <= radius * radius {
                let px = center_x as i32 + rel_x;
                let py = center_y as i32 + rel_y;

                let shade_factor = ((rel_x + rel_y + 20) * 255 / 40).clamp(0, 255) as u32;
                let base_color = blend_colors(COLOR_BLUE_LIGHT, COLOR_BLUE, shade_factor as u8);

                let dist = isqrt(dist_sq);
                let edge_factor = if dist > radius - 3 {
                    ((dist - (radius - 3)) * 60 / 3).min(60)
                } else {
                    0
                };
                let final_color = blend_colors(base_color, 0xFF000000, edge_factor as u8);

                put_pixel(px as u32, py as u32, final_color);
            }
        }
    }

    for offset in [-6i32, 0, 6].iter() {
        for dy in 0..radius * 2 {
            let rel_y = dy as i32 - radius as i32;
            let y_factor = (radius as i32 * radius as i32 - rel_y * rel_y).max(0);
            let max_x = isqrt(y_factor as u32) as i32;

            let curve = *offset * (radius as i32 - rel_y.abs()) / radius as i32;
            let lx = center_x as i32 + curve;
            let ly = center_y as i32 + rel_y;

            if (lx - center_x as i32).abs() < max_x {
                put_pixel(lx as u32, ly as u32, 0xE0FFFFFF);
            }
        }
    }

    for offset in [-6i32, 0, 6].iter() {
        let ly = center_y as i32 + offset;
        let y_offset = offset.abs() as u32;
        let line_radius = isqrt(radius * radius - y_offset * y_offset);

        for dx in 0..line_radius * 2 {
            let rel_x = dx as i32 - line_radius as i32;
            let lx = center_x as i32 + rel_x;
            put_pixel(lx as u32, ly as u32, 0xC0FFFFFF);
        }
    }
}

pub(super) fn draw_wallet_icon(cx: u32, cy: u32) {
    draw_icon_plate(cx, cy, 40);

    let x = cx - 14;
    let y = cy - 10;

    fill_rect(x + 3, y + 4, 24, 16, 0xFF1A1025);
    fill_rect(x + 1, y + 2, 26, 18, COLOR_PURPLE);
    fill_rect(x + 1, y + 2, 26, 5, COLOR_PURPLE_DARK);

    for px in 0..24u32 {
        let alpha = 50 - (px * 50 / 24);
        put_pixel(x + 2 + px, y + 3, (alpha << 24) | 0xFFFFFF);
    }

    fill_rect(x + 3, y + 9, 20, 9, 0xFF0D0A14);
    fill_rect(x + 5, y + 11, 12, 5, 0xFF2A2040);
    fill_rect(x + 5, y + 11, 12, 1, 0x30FFFFFF);

    super::sidebar_utils::draw_circle_filled(x + 23, y + 12, 3, 0xFFFFD700);
    put_pixel(x + 22, y + 11, 0x60FFFFFF);
}
