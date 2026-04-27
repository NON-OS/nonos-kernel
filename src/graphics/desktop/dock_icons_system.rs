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

use super::dock_helpers::{atan2_approx, draw_circle_small, draw_icon_plate, isqrt};
use crate::graphics::framebuffer::{fill_rect, put_pixel};

const COLOR_CYAN: u32 = 0xFF22D3EE;
const COLOR_PURPLE: u32 = 0xFFA78BFA;
const COLOR_LIME: u32 = 0xFF34D399;
const COLOR_BLUE: u32 = 0xFF60A5FA;

const PLATE_BLUE: u32 = 0xFF0F172A;
const PLATE_GREEN: u32 = 0xFF0D1F17;
const PLATE_PURPLE: u32 = 0xFF1E1B2E;

pub(super) fn draw_monitor_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_GREEN);

    let ox = x + 4;
    let oy = y + 5;
    let mw = size - 8;
    let mh = size - 14;

    fill_rect(ox, oy, mw, mh, 0xFF0F1F17);
    fill_rect(ox + 2, oy + 2, mw - 4, mh - 4, 0xFF0A1A12);

    let bar_heights: [u32; 7] = [12, 8, 16, 10, 6, 14, 9];
    let bar_w = (mw - 8) / 7;
    let max_h = mh - 8;

    for (i, &h) in bar_heights.iter().enumerate() {
        let bar_x = ox + 4 + (i as u32) * (bar_w + 1);
        let actual_h = (h * max_h / 18).min(max_h);
        let bar_y = oy + mh - 3 - actual_h;
        fill_rect(bar_x, bar_y, bar_w, actual_h, COLOR_LIME);
    }

    fill_rect(ox + mw / 2 - 4, oy + mh, 8, 3, 0xFF374151);
    fill_rect(ox + mw / 2 - 6, oy + mh + 3, 12, 2, 0xFF4B5563);
}

pub(super) fn draw_gear_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_BLUE);

    let cx = x + size / 2;
    let cy = y + size / 2;
    let outer_r = size / 2 - 5;
    let hole_r = outer_r / 3;

    for dy in 0..outer_r * 2 + 2 {
        for dx in 0..outer_r * 2 + 2 {
            let rel_x = dx as i32 - outer_r as i32 - 1;
            let rel_y = dy as i32 - outer_r as i32 - 1;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            let dist = isqrt(dist_sq);

            let angle = atan2_approx(rel_y, rel_x);
            let tooth_phase = ((angle + 22) / 45) % 2;
            let effective_outer = if tooth_phase == 0 { outer_r } else { outer_r - 3 };

            if dist <= effective_outer && dist >= hole_r {
                let px = cx as i32 + rel_x;
                let py = cy as i32 + rel_y;
                put_pixel(px as u32, py as u32, COLOR_CYAN);
            }
        }
    }

    for dy in 0..hole_r * 2 + 2 {
        for dx in 0..hole_r * 2 + 2 {
            let rel_x = dx as i32 - hole_r as i32 - 1;
            let rel_y = dy as i32 - hole_r as i32 - 1;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            if dist_sq <= hole_r * hole_r {
                put_pixel(cx - hole_r - 1 + dx, cy - hole_r - 1 + dy, PLATE_BLUE);
            }
        }
    }
}

pub(super) fn draw_globe_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_BLUE);

    let cx = x + size / 2;
    let cy = y + size / 2;
    let radius = size / 2 - 5;

    for dy in 0..radius * 2 + 2 {
        for dx in 0..radius * 2 + 2 {
            let rel_x = dx as i32 - radius as i32 - 1;
            let rel_y = dy as i32 - radius as i32 - 1;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;

            if dist_sq <= radius * radius {
                let px = cx as i32 + rel_x;
                let py = cy as i32 + rel_y;
                put_pixel(px as u32, py as u32, COLOR_BLUE);
            }
        }
    }

    for offset in [-7i32, 0, 7].iter() {
        let line_y = cy as i32 + offset;
        let r2 = (radius * radius) as i32 - offset * offset;
        if r2 > 0 {
            let line_r = isqrt(r2 as u32);
            for lx in 0..line_r * 2 {
                let px = cx - line_r + lx;
                put_pixel(px, line_y as u32, 0x50FFFFFF);
            }
        }
    }

    for offset in [-5i32, 0, 5].iter() {
        for dy in 0..radius * 2 {
            let rel_y = dy as i32 - radius as i32;
            let curve = (*offset * (radius as i32 - rel_y.abs())) / (radius as i32);
            let px = (cx as i32 + curve) as u32;
            let py = cy - radius + dy;
            let r2 = (radius * radius) as i32 - rel_y * rel_y;
            if r2 > 0 && (px as i32 - cx as i32).abs() < isqrt(r2 as u32) as i32 {
                put_pixel(px, py, 0x40FFFFFF);
            }
        }
    }
}

pub(super) fn draw_info_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_PURPLE);

    let cx = x + size / 2;
    let cy = y + size / 2;
    let radius = size / 2 - 5;

    for dy in 0..radius * 2 + 2 {
        for dx in 0..radius * 2 + 2 {
            let rel_x = dx as i32 - radius as i32 - 1;
            let rel_y = dy as i32 - radius as i32 - 1;
            let dist_sq = (rel_x * rel_x + rel_y * rel_y) as u32;
            if dist_sq <= radius * radius {
                put_pixel(cx - radius - 1 + dx, cy - radius - 1 + dy, COLOR_PURPLE);
            }
        }
    }

    draw_circle_small(cx, cy - radius / 2, 2, 0xFF1E1B2E);
    fill_rect(cx - 2, cy - 2, 5, radius, 0xFF1E1B2E);
    fill_rect(cx - 4, cy - 2, 9, 2, 0xFF1E1B2E);
    fill_rect(cx - 4, cy + radius - 4, 9, 2, 0xFF1E1B2E);
}
