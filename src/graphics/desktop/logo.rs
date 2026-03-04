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

const COLOR_LOGO_BG: u32 = 0xFF00B8D4;
const COLOR_LOGO_STROKE: u32 = 0xFF0A1A1A;

pub(super) fn draw(w: u32, h: u32) {
    let logo_size = 100u32;
    let cx = SIDEBAR_WIDTH + ((w - SIDEBAR_WIDTH) / 2);
    let cy = MENU_BAR_HEIGHT + ((h - MENU_BAR_HEIGHT - DOCK_HEIGHT) / 2);
    let logo_x = cx - logo_size / 2;
    let logo_y = cy - logo_size / 2 - 20;

    fill_rounded_rect(logo_x, logo_y, logo_size, logo_size, 20, COLOR_LOGO_BG);

    let symbol_x = logo_x + logo_size / 2;
    let symbol_y = logo_y + logo_size / 2;
    let outer_r = 32u32;
    let inner_r = 24u32;
    let stroke_w = 8u32;

    for dy in 0..=outer_r {
        for dx in 0..=outer_r {
            let dist_sq = dx * dx + dy * dy;
            if dist_sq <= outer_r * outer_r && dist_sq >= inner_r * inner_r {
                put_pixel(symbol_x + dx, symbol_y + dy, COLOR_LOGO_STROKE);
                if dx > 0 { put_pixel(symbol_x - dx, symbol_y + dy, COLOR_LOGO_STROKE); }
                if dy > 0 { put_pixel(symbol_x + dx, symbol_y - dy, COLOR_LOGO_STROKE); }
                if dx > 0 && dy > 0 { put_pixel(symbol_x - dx, symbol_y - dy, COLOR_LOGO_STROKE); }
            }
        }
    }

    for i in 0..(outer_r * 2 + stroke_w) {
        let px = symbol_x as i32 - outer_r as i32 - (stroke_w / 2) as i32 + i as i32;
        let py = symbol_y as i32 + outer_r as i32 + (stroke_w / 2) as i32 - i as i32;

        for w in 0..stroke_w {
            let wpx = px + (w as i32 - stroke_w as i32 / 2) / 2;
            let wpy = py + (w as i32 - stroke_w as i32 / 2) / 2;

            let dx = (wpx - symbol_x as i32).unsigned_abs();
            let dy = (wpy - symbol_y as i32).unsigned_abs();
            let dist_sq = dx * dx + dy * dy;

            if dist_sq <= outer_r * outer_r {
                if wpx >= logo_x as i32 && wpx < (logo_x + logo_size) as i32 &&
                   wpy >= logo_y as i32 && wpy < (logo_y + logo_size) as i32 {
                    put_pixel(wpx as u32, wpy as u32, COLOR_LOGO_STROKE);
                }
            }
        }
    }
}

fn fill_rounded_rect(x: u32, y: u32, w: u32, h: u32, r: u32, color: u32) {
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
