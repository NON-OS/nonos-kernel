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

use crate::graphics::framebuffer::fill_rect;
use super::dock_helpers::{draw_icon_plate, draw_circle_small};

const COLOR_RED: u32 = 0xFFEF5350;
const COLOR_GOLD: u32 = 0xFFFFB800;
const COLOR_GOLD_DARK: u32 = 0xFFCC9200;
const COLOR_LIME: u32 = 0xFF00E676;
const COLOR_ORANGE: u32 = 0xFFFF9800;
const COLOR_WHITE: u32 = 0xFFFFFFFF;
const COLOR_CYAN: u32 = 0xFF00D4FF;
const COLOR_PURPLE: u32 = 0xFFBB86FC;
const COLOR_PURPLE_DARK: u32 = 0xFF9966DD;

const PLATE_TERMINAL: u32 = 0xFF0D1117;
const PLATE_DARK: u32 = 0xFF12161C;
const PLATE_GOLD: u32 = 0xFF1A1608;
const PLATE_PURPLE: u32 = 0xFF1A1020;

pub(super) fn draw_terminal_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_TERMINAL);

    let ox = x + 5;
    let oy = y + 6;
    let tw = size - 10;
    let th = size - 12;

    fill_rect(ox, oy, tw, th, 0xFF0A0E14);
    fill_rect(ox, oy, tw, 5, 0xFF21262D);

    let buttons = [COLOR_RED, COLOR_GOLD, COLOR_LIME];
    for (i, &color) in buttons.iter().enumerate() {
        draw_circle_small(ox + 4 + i as u32 * 5, oy + 2, 1, color);
    }

    let text_y = oy + 9;

    fill_rect(ox + 3, text_y, 2, 2, COLOR_LIME);
    fill_rect(ox + 3, text_y + 6, 2, 2, COLOR_LIME);
    fill_rect(ox + 3, text_y + 12, 2, 2, COLOR_LIME);

    fill_rect(ox + 7, text_y, 12, 2, 0xFF6E7681);
    fill_rect(ox + 7, text_y + 6, 18, 2, 0xFF6E7681);
    fill_rect(ox + 7, text_y + 12, 8, 2, 0xFF6E7681);

    fill_rect(ox + 17, text_y + 12, 3, 2, COLOR_WHITE);
}

pub(super) fn draw_folder_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_GOLD);

    let ox = x + 5;
    let oy = y + 8;

    fill_rect(ox + 3, oy + 3, size - 13, 22, COLOR_GOLD_DARK);
    fill_rect(ox, oy + 4, size - 10, 20, COLOR_GOLD);
    fill_rect(ox, oy, 14, 6, COLOR_GOLD);
    fill_rect(ox + 13, oy + 2, 3, 3, COLOR_GOLD);
    fill_rect(ox + 2, oy + 8, size - 14, 1, 0x40FFFFFF);
    fill_rect(ox + 2, oy + 22, size - 14, 1, 0x20000000);
}

pub(super) fn draw_document_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, PLATE_DARK);

    let ox = x + 10;
    let oy = y + 4;
    let pw = size - 20;
    let ph = size - 8;

    fill_rect(ox + 2, oy + 2, pw, ph, 0xFF1A1E24);
    fill_rect(ox, oy, pw, ph, COLOR_WHITE);

    let fold_size = 8u32;
    fill_rect(ox + pw - fold_size, oy, fold_size, fold_size, 0xFFD0D4DA);
    for i in 0..fold_size {
        fill_rect(ox + pw - fold_size + i, oy + i, fold_size - i, 1, 0xFFB8BCC4);
    }

    let line_colors = [0xFF3D4450, 0xFF4D5560, 0xFF3D4450, 0xFF4D5560, 0xFF3D4450];
    let line_widths = [pw - 10, pw - 6, pw - 12, pw - 8, pw - 14];
    for (i, (&color, &width)) in line_colors.iter().zip(line_widths.iter()).enumerate() {
        if width > 4 {
            fill_rect(ox + 3, oy + 12 + i as u32 * 5, width.min(pw - 6), 2, color);
        }
    }
}

pub(super) fn draw_calculator_icon(x: u32, y: u32, size: u32) {
    draw_icon_plate(x, y, size, 0xFF1A1E24);

    let ox = x + 6;
    let oy = y + 4;
    let cw = size - 12;
    let ch = size - 8;

    fill_rect(ox, oy, cw, ch, 0xFF21262D);
    fill_rect(ox + 2, oy + 2, cw - 4, 10, 0xFF0D1117);
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
                0xFF3D4450
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

    fill_rect(ox, oy + 5, ww, wh - 5, COLOR_PURPLE);
    fill_rect(ox, oy, ww, 7, COLOR_PURPLE_DARK);
    fill_rect(ox + 2, oy + 1, ww - 4, 1, 0x30FFFFFF);
    fill_rect(ox + 3, oy + 12, ww - 6, 14, 0xFF0D0A14);
    fill_rect(ox + 5, oy + 14, ww - 10, 8, 0xFF2A2040);
    fill_rect(ox + 5, oy + 14, ww - 10, 1, 0x20FFFFFF);

    let cx = ox + ww / 2;
    let cy = oy + wh / 2 + 4;
    for i in 0..5u32 {
        let w = if i < 3 { i + 1 } else { 5 - i };
        fill_rect(cx - w, cy - 2 + i, w * 2, 1, COLOR_CYAN);
    }
    for i in 0..4u32 {
        let w = 3 - i;
        fill_rect(cx - w, cy + 3 + i, w * 2 + 1, 1, COLOR_CYAN);
    }
}
