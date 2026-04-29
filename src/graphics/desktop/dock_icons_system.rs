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

//! System dock icons - Settings, Browser, and other system apps.

use super::dock_helpers::{draw_circle_small, draw_icon_plate};
use crate::graphics::framebuffer::fill_rect;

const COLOR_GRAY: u32 = 0xFF9CA3AF;
const COLOR_BLUE: u32 = 0xFF3B82F6;
const COLOR_WHITE: u32 = 0xFFFFFFFF;

const PLATE_SYSTEM: u32 = 0xFF1F2937;
const PLATE_BROWSER: u32 = 0xFF0C1929;

/// Draw settings gear icon
pub fn draw_settings_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_SYSTEM);
    let cx = x + size / 2;
    let cy = y + size / 2;

    // Outer ring (gear teeth represented as rectangles)
    let teeth = 8u32;
    let outer_r = size / 3;
    let inner_r = size / 5;

    // Draw gear body - teeth at cardinal + diagonal positions
    for i in 0..teeth {
        let tooth_w = 4;
        let tooth_h = 4;
        let (dx, dy) = match i % 8 {
            0 => (0i32, -(outer_r as i32)),
            1 => ((outer_r as i32 * 7 / 10), -(outer_r as i32 * 7 / 10)),
            2 => (outer_r as i32, 0),
            3 => ((outer_r as i32 * 7 / 10), (outer_r as i32 * 7 / 10)),
            4 => (0, outer_r as i32),
            5 => (-(outer_r as i32 * 7 / 10), (outer_r as i32 * 7 / 10)),
            6 => (-(outer_r as i32), 0),
            _ => (-(outer_r as i32 * 7 / 10), -(outer_r as i32 * 7 / 10)),
        };

        let tx = (cx as i32 + dx - tooth_w as i32 / 2).max(0) as u32;
        let ty = (cy as i32 + dy - tooth_h as i32 / 2).max(0) as u32;
        fill_rect(tx, ty, tooth_w, tooth_h, COLOR_GRAY);
    }

    // Draw center circle
    draw_circle_small(cx, cy, inner_r, COLOR_GRAY);
    draw_circle_small(cx, cy, inner_r - 3, PLATE_SYSTEM);
}

/// Draw browser/globe icon
pub fn draw_browser_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_BROWSER);
    let cx = x + size / 2;
    let cy = y + size / 2;
    let r = size / 3;

    // Draw globe
    draw_circle_small(cx, cy, r, COLOR_BLUE);

    // Draw latitude lines
    fill_rect(cx - r + 2, cy - r / 2, r * 2 - 4, 1, COLOR_WHITE);
    fill_rect(cx - r + 2, cy, r * 2 - 4, 1, COLOR_WHITE);
    fill_rect(cx - r + 2, cy + r / 2, r * 2 - 4, 1, COLOR_WHITE);

    // Draw longitude line
    fill_rect(cx - 1, cy - r + 2, 2, r * 2 - 4, COLOR_WHITE);
}

/// Draw power icon
pub fn draw_power_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF7F1D1D);
    let cx = x + size / 2;
    let cy = y + size / 2;

    // Power symbol - circle with line at top
    let r = size / 4;
    draw_circle_small(cx, cy + 2, r, 0xFFEF4444);
    draw_circle_small(cx, cy + 2, r - 3, 0xFF7F1D1D);

    // Vertical line
    fill_rect(cx - 1, cy - r / 2, 3, r, 0xFFEF4444);
}
