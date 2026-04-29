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

//! Menubar icon rendering - used for status area icons.

use crate::graphics::framebuffer::{fill_rect, put_pixel};

const COLOR_WHITE: u32 = 0xFFFFFFFF;
const COLOR_GRAY: u32 = 0xFF9CA3AF;

/// Draw volume speaker icon
pub fn draw_volume_icon(x: u32, y: u32, volume: u8, muted: bool) {
    let color = if muted { 0xFF6B7280 } else { COLOR_WHITE };

    // Speaker body
    fill_rect(x, y + 4, 3, 6, color);
    fill_rect(x + 3, y + 2, 3, 10, color);

    // Sound waves (show based on volume)
    if !muted && volume > 0 {
        // First wave
        put_pixel(x + 8, y + 5, color);
        put_pixel(x + 8, y + 6, color);
        put_pixel(x + 8, y + 7, color);
        put_pixel(x + 8, y + 8, color);

        if volume > 33 {
            // Second wave
            put_pixel(x + 10, y + 3, color);
            put_pixel(x + 10, y + 4, color);
            put_pixel(x + 10, y + 9, color);
            put_pixel(x + 10, y + 10, color);
        }

        if volume > 66 {
            // Third wave
            put_pixel(x + 12, y + 2, color);
            put_pixel(x + 12, y + 11, color);
        }
    }

    // Mute X
    if muted {
        put_pixel(x + 10, y + 4, 0xFFEF4444);
        put_pixel(x + 11, y + 5, 0xFFEF4444);
        put_pixel(x + 12, y + 6, 0xFFEF4444);
        put_pixel(x + 12, y + 4, 0xFFEF4444);
        put_pixel(x + 11, y + 5, 0xFFEF4444);
        put_pixel(x + 10, y + 6, 0xFFEF4444);
    }
}

/// Draw Bluetooth icon
pub fn draw_bluetooth_icon(x: u32, y: u32, connected: bool) {
    let color = if connected { 0xFF3B82F6 } else { COLOR_GRAY };

    // Draw B shape
    fill_rect(x + 5, y, 2, 14, color);
    put_pixel(x + 7, y + 1, color);
    put_pixel(x + 8, y + 2, color);
    put_pixel(x + 9, y + 3, color);
    put_pixel(x + 8, y + 4, color);
    put_pixel(x + 7, y + 5, color);
    put_pixel(x + 6, y + 6, color);
    put_pixel(x + 5, y + 7, color);
    put_pixel(x + 6, y + 8, color);
    put_pixel(x + 7, y + 9, color);
    put_pixel(x + 8, y + 10, color);
    put_pixel(x + 9, y + 11, color);
    put_pixel(x + 8, y + 12, color);
    put_pixel(x + 7, y + 13, color);

    // Left triangles
    put_pixel(x + 3, y + 3, color);
    put_pixel(x + 2, y + 4, color);
    put_pixel(x + 3, y + 5, color);
    put_pixel(x + 3, y + 9, color);
    put_pixel(x + 2, y + 10, color);
    put_pixel(x + 3, y + 11, color);
}

/// Draw spotlight/search icon
pub fn draw_search_icon(x: u32, y: u32) {
    let color = COLOR_WHITE;

    // Magnifying glass circle
    for r in 4..6u32 {
        for angle in 0..16u32 {
            let a = (angle * 360 / 16) as i32;
            let dx = (a.abs() % 90 - 45) * r as i32 / 45;
            let dy = ((90 - (a.abs() % 90)).min(a.abs() % 90)) * r as i32 / 45;
            put_pixel((x + 5 + r).wrapping_sub(dx.unsigned_abs()),
                     (y + 5 + r).wrapping_sub(dy.unsigned_abs()), color);
        }
    }

    // Handle
    fill_rect(x + 10, y + 10, 4, 2, color);
    fill_rect(x + 11, y + 11, 3, 2, color);
}

/// Draw control center icon (sliders)
pub fn draw_control_center_icon(x: u32, y: u32) {
    let color = COLOR_WHITE;

    // Three horizontal sliders
    fill_rect(x, y + 2, 14, 2, color);
    fill_rect(x + 10, y + 1, 3, 4, 0xFF3B82F6);

    fill_rect(x, y + 6, 14, 2, color);
    fill_rect(x + 4, y + 5, 3, 4, 0xFF3B82F6);

    fill_rect(x, y + 10, 14, 2, color);
    fill_rect(x + 8, y + 9, 3, 4, 0xFF3B82F6);
}
