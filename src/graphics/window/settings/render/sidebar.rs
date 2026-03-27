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

use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_TEXT_WHITE};
use super::main::draw_string;
use crate::graphics::window::settings::state::SIDEBAR_WIDTH;

pub(super) fn draw_sidebar(x: u32, y: u32, h: u32, current_page: u8) {
    fill_rect(x, y, SIDEBAR_WIDTH, h, 0xFF1A1A1E);
    fill_rect(x + SIDEBAR_WIDTH - 1, y, 1, h, 0xFF2C2C30);
    draw_string(x + 16, y + 16, b"Settings", 0xFF6E6E72);

    let icons: [u8; 5] = [0x1F, 0x57, 0x40, 0x2A, 0x26];
    let categories: [&[u8]; 5] = [b"Privacy", b"Network", b"Wallpapers", b"System", b"Power"];
    let colors: [u32; 5] = [0xFF8B5CF6, 0xFF3B82F6, 0xFFF59E0B, 0xFF6B7280, 0xFFEF4444];

    for (i, cat) in categories.iter().enumerate() {
        let ty = y + 50 + (i as u32) * 44;
        let is_sel = current_page == i as u8;
        if is_sel {
            draw_rounded_selection(x + 8, ty, SIDEBAR_WIDTH - 16, 36, 0xFF2A2A32);
        }
        fill_rect(x + 16, ty + 6, 24, 24, colors[i]);
        draw_string(x + 16 + 7, ty + 12, &[icons[i]], 0xFFFFFFFF);
        let text_color = if is_sel { COLOR_TEXT_WHITE } else { 0xFF9CA3AF };
        draw_string(x + 48, ty + 12, cat, text_color);
    }
}

fn draw_rounded_selection(x: u32, y: u32, w: u32, h: u32, color: u32) {
    let r = 8u32;
    fill_rect(x + r, y, w - 2 * r, h, color);
    fill_rect(x, y + r, r, h - 2 * r, color);
    fill_rect(x + w - r, y + r, r, h - 2 * r, color);
    for corner in 0..4u32 {
        let (cx, cy) = match corner {
            0 => (x + r, y + r),
            1 => (x + w - r - 1, y + r),
            2 => (x + r, y + h - r - 1),
            _ => (x + w - r - 1, y + h - r - 1),
        };
        for dy in 0..=r {
            for dx in 0..=r {
                if dx * dx + dy * dy <= r * r {
                    let (px, py) = match corner {
                        0 => (cx - dx, cy - dy),
                        1 => (cx + dx, cy - dy),
                        2 => (cx - dx, cy + dy),
                        _ => (cx + dx, cy + dy),
                    };
                    put_pixel(px, py, color);
                }
            }
        }
    }
}
