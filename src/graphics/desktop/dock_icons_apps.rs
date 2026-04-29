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

use super::dock_helpers::{draw_circle_small, draw_icon_plate};
use crate::graphics::framebuffer::fill_rect;

const COLOR_RED: u32 = 0xFFEF4444;
const COLOR_GOLD: u32 = 0xFFFBBF24;
const COLOR_GOLD_DARK: u32 = 0xFFD97706;
const COLOR_LIME: u32 = 0xFF34D399;
const COLOR_ORANGE: u32 = 0xFFF97316;
const COLOR_WHITE: u32 = 0xFFFFFFFF;
const COLOR_CYAN: u32 = 0xFF22D3EE;
const COLOR_PURPLE: u32 = 0xFFA78BFA;
const COLOR_PURPLE_DARK: u32 = 0xFF8B5CF6;

const PLATE_TERMINAL: u32 = 0xFF111827;
const PLATE_DARK: u32 = 0xFF1F2937;
const PLATE_GOLD: u32 = 0xFF1C1917;
const PLATE_PURPLE: u32 = 0xFF1E1B2E;

pub(super) fn draw_terminal_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_TERMINAL);

    let ox = x + 5;
    let oy = y + 6;
    let tw = size - 10;
    let th = size - 12;

    fill_rect(ox, oy, tw, th, 0xFF0F172A);
    fill_rect(ox, oy, tw, 5, 0xFF1E293B);

    let buttons = [COLOR_RED, COLOR_GOLD, COLOR_LIME];
    for (i, &color) in buttons.iter().enumerate() {
        draw_circle_small(ox + 4 + i as u32 * 5, oy + 2, 1, color);
    }

    let text_y = oy + 9;
    fill_rect(ox + 3, text_y, 2, 2, COLOR_LIME);
    fill_rect(ox + 3, text_y + 6, 2, 2, COLOR_LIME);
    fill_rect(ox + 3, text_y + 12, 2, 2, COLOR_LIME);
    fill_rect(ox + 7, text_y, 12, 2, 0xFF64748B);
    fill_rect(ox + 7, text_y + 6, 18, 2, 0xFF64748B);
    fill_rect(ox + 7, text_y + 12, 8, 2, 0xFF64748B);
    fill_rect(ox + 17, text_y + 12, 3, 2, COLOR_WHITE);
}

pub(super) fn draw_folder_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_GOLD);

    let ox = x + 5;
    let oy = y + 8;

    fill_rect(ox + 2, oy + 3, size - 12, 21, COLOR_GOLD_DARK);
    fill_rect(ox, oy + 4, size - 10, 19, COLOR_GOLD);
    fill_rect(ox, oy, 14, 5, COLOR_GOLD);
    fill_rect(ox + 13, oy + 2, 3, 3, COLOR_GOLD);
    fill_rect(ox + 2, oy + 7, size - 14, 1, 0x30FFFFFF);
}

pub(super) fn draw_document_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_DARK);

    let ox = x + 10;
    let oy = y + 4;
    let pw = size - 20;
    let ph = size - 8;

    fill_rect(ox + 2, oy + 2, pw, ph, 0xFF1E293B);
    fill_rect(ox, oy, pw, ph, COLOR_WHITE);

    let fold_size = 7u32;
    fill_rect(ox + pw - fold_size, oy, fold_size, fold_size, 0xFFE5E7EB);
    for i in 0..fold_size {
        fill_rect(ox + pw - fold_size + i, oy + i, fold_size - i, 1, 0xFFD1D5DB);
    }

    let line_widths = [pw - 8, pw - 4, pw - 10, pw - 6, pw - 12];
    for (i, &width) in line_widths.iter().enumerate() {
        if width > 4 {
            fill_rect(ox + 3, oy + 12 + i as u32 * 5, width.min(pw - 6), 2, 0xFF9CA3AF);
        }
    }
}

pub(super) fn draw_calculator_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF1F2937);

    let ox = x + 6;
    let oy = y + 4;
    let cw = size - 12;
    let ch = size - 8;

    fill_rect(ox, oy, cw, ch, 0xFF374151);
    fill_rect(ox + 2, oy + 2, cw - 4, 10, 0xFF111827);
    fill_rect(ox + 4, oy + 5, 12, 4, COLOR_CYAN);

    let btn_w = (cw - 8) / 4;
    let btn_h = (ch - 18) / 4;

    for row in 0..4u32 {
        for col in 0..4u32 {
            let is_operator = col == 3;
            let is_equals = row == 3 && col == 3;
            let color = if is_equals {
                COLOR_LIME
            } else if is_operator {
                COLOR_ORANGE
            } else {
                0xFF4B5563
            };
            let bx = ox + 2 + col * (btn_w + 1);
            let by = oy + 14 + row * (btn_h + 1);
            fill_rect(bx, by, btn_w, btn_h, color);
        }
    }
}

pub(super) fn draw_wallet_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_PURPLE);
    let ox = x + 5;
    let oy = y + 5;
    let ww = size - 10;
    let wh = size - 10;
    fill_rect(ox, oy + 4, ww, wh - 4, COLOR_PURPLE);
    fill_rect(ox, oy, ww, 6, COLOR_PURPLE_DARK);
    fill_rect(ox + 2, oy + 1, ww - 4, 1, 0x20FFFFFF);
    fill_rect(ox + 3, oy + 11, ww - 6, 13, 0xFF1E1B2E);
    fill_rect(ox + 5, oy + 13, ww - 10, 8, 0xFF312E41);
    let cx = ox + ww / 2;
    let cy = oy + wh / 2 + 3;
    for i in 0..5u32 {
        let w = if i < 3 { i + 1 } else { 5 - i };
        fill_rect(cx - w, cy - 2 + i, w * 2, 1, COLOR_CYAN);
    }
}

pub(super) fn draw_marketplace_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF0C1929);
    let ox = x + 6;
    let oy = y + 6;
    fill_rect(ox + 4, oy + 2, size - 20, 5, 0xFF38BDF8);
    fill_rect(ox + 2, oy + 7, size - 16, 19, 0xFF0EA5E9);
    fill_rect(ox + 6, oy + 11, 8, 11, 0xFFBAE6FD);
    fill_rect(ox + 18, oy + 11, 8, 11, 0xFFBAE6FD);
    fill_rect(ox + 6, oy + 24, 20, 3, 0xFF7DD3FC);
}

pub(super) fn draw_agents_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF1E1033);
    let cx = x + size / 2;
    let cy = y + size / 2;
    for i in 0..8u32 {
        let r = 12 - i;
        fill_rect(cx - r, cy - r + i * 2, r * 2, 2, 0xFFC084FC);
    }
    fill_rect(cx - 3, cy - 6, 6, 6, 0xFFFFFFFF);
    fill_rect(cx - 2, cy + 2, 4, 8, 0xFFC084FC);
}

pub(super) fn draw_process_manager_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF1F2937);
    let ox = x + 6;
    let oy = y + 6;

    // Activity bars
    fill_rect(ox + 2, oy + 20, 6, 8, COLOR_LIME);
    fill_rect(ox + 10, oy + 14, 6, 14, COLOR_CYAN);
    fill_rect(ox + 18, oy + 8, 6, 20, COLOR_GOLD);

    // CPU meter at top
    fill_rect(ox, oy, size - 12, 4, 0xFF374151);
    fill_rect(ox, oy, (size - 12) * 7 / 10, 4, COLOR_LIME);
}

pub(super) fn draw_settings_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF374151);
    let cx = x + size / 2;
    let cy = y + size / 2;

    // Gear teeth
    let outer_r = size / 3;
    let inner_r = size / 5;
    for i in 0..8u32 {
        let (dx, dy): (i32, i32) = match i {
            0 => (0, -(outer_r as i32)),
            1 => ((outer_r as i32 * 7) / 10, -((outer_r as i32 * 7) / 10)),
            2 => (outer_r as i32, 0),
            3 => ((outer_r as i32 * 7) / 10, (outer_r as i32 * 7) / 10),
            4 => (0, outer_r as i32),
            5 => (-((outer_r as i32 * 7) / 10), (outer_r as i32 * 7) / 10),
            6 => (-(outer_r as i32), 0),
            _ => (-((outer_r as i32 * 7) / 10), -((outer_r as i32 * 7) / 10)),
        };
        let tx = ((cx as i32 + dx - 2).max(0)) as u32;
        let ty = ((cy as i32 + dy - 2).max(0)) as u32;
        fill_rect(tx, ty, 5, 5, 0xFF9CA3AF);
    }

    // Center circle
    draw_circle_small(cx, cy, inner_r, 0xFF9CA3AF);
    draw_circle_small(cx, cy, inner_r - 4, 0xFF374151);
}

pub(super) fn draw_browser_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF0F172A);
    let cx = x + size / 2;
    let cy = y + size / 2;
    let r = size / 3;

    // Globe
    draw_circle_small(cx, cy, r, 0xFF3B82F6);

    // Latitude lines
    fill_rect(cx - r + 4, cy - r / 2, r * 2 - 8, 1, COLOR_WHITE);
    fill_rect(cx - r + 2, cy, r * 2 - 4, 1, COLOR_WHITE);
    fill_rect(cx - r + 4, cy + r / 2, r * 2 - 8, 1, COLOR_WHITE);

    // Longitude
    fill_rect(cx - 1, cy - r + 4, 2, r * 2 - 8, COLOR_WHITE);
}

pub(super) fn draw_about_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF1E3A5F);
    let cx = x + size / 2;
    let cy = y + size / 2;

    // N letter stylized
    fill_rect(cx - 8, cy - 8, 4, 16, COLOR_WHITE);
    fill_rect(cx + 4, cy - 8, 4, 16, COLOR_WHITE);

    // Diagonal
    for i in 0..12u32 {
        fill_rect(cx - 6 + i, cy - 6 + i, 3, 2, COLOR_WHITE);
    }

    // Slash through (Ø style)
    fill_rect(cx - 6, cy + 6, 12, 2, COLOR_CYAN);
}
