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

use crate::graphics::components::primitives::rounded_rect;
use crate::graphics::design_system::colors::*;
use crate::graphics::font::draw_char;
use crate::graphics::framebuffer::{fill_rect, put_pixel};

pub(super) const PADDING: u32 = 12;
pub(super) const DISPLAY_H: u32 = 90;
const BTN_ROWS: u32 = 5;
const BTN_COLS: u32 = 4;
const BTN_GAP: u32 = 10;

pub(super) fn draw_buttons(x: u32, y: u32, w: u32, h: u32) {
    let btn_area_h = h - DISPLAY_H - PADDING * 2 - 10;
    let btn_h = (btn_area_h - BTN_GAP * (BTN_ROWS - 1)) / BTN_ROWS;
    let btn_w = (w - PADDING * 2 - BTN_GAP * (BTN_COLS - 1)) / BTN_COLS;
    let btn_y_start = y + DISPLAY_H + PADDING + 10;

    let buttons: [[(&[u8], u32, u32); 4]; 5] = [
        [
            (b"AC", CALC_BTN_FUNCTION, TEXT_INVERSE),
            (b"+/-", CALC_BTN_FUNCTION, TEXT_INVERSE),
            (b"%", CALC_BTN_FUNCTION, TEXT_INVERSE),
            (b"\xf7", CALC_BTN_OPERATOR, TEXT_PRIMARY),
        ],
        [
            (b"1", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"2", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"3", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"\xd7", CALC_BTN_OPERATOR, TEXT_PRIMARY),
        ],
        [
            (b"4", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"5", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"6", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"-", CALC_BTN_OPERATOR, TEXT_PRIMARY),
        ],
        [
            (b"7", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"8", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"9", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"+", CALC_BTN_OPERATOR, TEXT_PRIMARY),
        ],
        [
            (b".", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"0", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"00", CALC_BTN_NUMBER, TEXT_PRIMARY),
            (b"=", CALC_BTN_EQUALS, TEXT_PRIMARY),
        ],
    ];

    for (row, btns) in buttons.iter().enumerate() {
        for (col, (label, bg, text_col)) in btns.iter().enumerate() {
            let bx = x + PADDING + (col as u32) * (btn_w + BTN_GAP);
            let by = btn_y_start + (row as u32) * (btn_h + BTN_GAP);
            rounded_rect(bx, by, btn_w, btn_h, 12, *bg);
            if row == 0 || col == 3 {
                for gy in 0..3u32 {
                    fill_rect(
                        bx + 12,
                        by + gy + 1,
                        btn_w - 24,
                        1,
                        ((20 - gy * 6) << 24) | 0xFFFFFF,
                    );
                }
            }
            let tw = label.len() as u32 * 10;
            let tx = bx + (btn_w - tw) / 2;
            let ty = by + (btn_h - 16) / 2;
            for (i, &ch) in label.iter().enumerate() {
                draw_char(tx + (i as u32) * 10, ty, ch, *text_col);
            }
        }
    }
}

pub(super) fn draw_clock_icon(x: u32, y: u32) {
    let color = 0xFF6E7A88;
    for dy in 0..12u32 {
        for dx in 0..12u32 {
            let d = (dx as i32 - 5) * (dx as i32 - 5) + (dy as i32 - 5) * (dy as i32 - 5);
            if d >= 16 && d <= 25 {
                put_pixel(x + dx, y + dy, color);
            }
        }
    }
    fill_rect(x + 5, y + 3, 1, 4, color);
    fill_rect(x + 5, y + 5, 3, 1, color);
}
