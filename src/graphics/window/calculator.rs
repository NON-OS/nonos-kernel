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

use core::sync::atomic::{AtomicBool, AtomicI64, AtomicU8, Ordering};
use crate::graphics::framebuffer::{fill_rect, put_pixel, COLOR_TEXT_WHITE};
use crate::graphics::font::draw_char;

const COLOR_BTN_NUM: u32 = 0xFF1A4D4D;
const COLOR_BTN_OP: u32 = 0xFF0D3333;
const COLOR_BTN_FUNC: u32 = 0xFF0D3333;
const COLOR_BTN_EQUALS: u32 = 0xFF00A0A0;
const COLOR_DISPLAY_BG: u32 = 0xFF0A1A1A;
const COLOR_EXPR: u32 = 0xFF7D8590;

pub(super) static CALC_DISPLAY: AtomicI64 = AtomicI64::new(0);
pub(super) static CALC_OPERAND: AtomicI64 = AtomicI64::new(0);
pub(super) static CALC_OPERATOR: AtomicU8 = AtomicU8::new(0);
pub(super) static CALC_NEW_INPUT: AtomicBool = AtomicBool::new(true);
pub(super) static CALC_EXPR_OP: AtomicU8 = AtomicU8::new(0);
pub(super) static CALC_EXPR_VAL: AtomicI64 = AtomicI64::new(0);
pub(super) static CALC_DECIMAL_POS: AtomicU8 = AtomicU8::new(0);

pub(super) fn draw_calculator(x: u32, y: u32, w: u32, h: u32) {
    let padding = 12u32;
    let display_h = 80u32;
    let btn_rows = 5u32;
    let btn_cols = 4u32;
    let btn_gap = 8u32;
    let btn_area_h = h - display_h - padding * 2 - 10;
    let btn_h = (btn_area_h - btn_gap * (btn_rows - 1)) / btn_rows;
    let btn_w = (w - padding * 2 - btn_gap * (btn_cols - 1)) / btn_cols;

    fill_rounded_rect(x + padding, y + padding, w - padding * 2, display_h, 8, COLOR_DISPLAY_BG);

    draw_clock_icon(x + w - padding - 20, y + padding + 8);

    let expr_op = CALC_EXPR_OP.load(Ordering::Relaxed);
    let expr_val = CALC_EXPR_VAL.load(Ordering::Relaxed);
    let display_val = CALC_DISPLAY.load(Ordering::Relaxed);

    if expr_op != 0 {
        let mut expr_x = x + w - padding - 20;
        let expr_y = y + padding + 18;

        let current = CALC_DISPLAY.load(Ordering::Relaxed);
        if !CALC_NEW_INPUT.load(Ordering::Relaxed) || CALC_OPERATOR.load(Ordering::Relaxed) == 0 {
            expr_x = draw_number_small(expr_x, expr_y, current, COLOR_EXPR);
            expr_x -= 16;
        }

        let op_ch = match expr_op {
            1 => b'+',
            2 => b'-',
            3 => 0xD7,
            4 => 0xF7,
            _ => b' ',
        };
        draw_char(expr_x, expr_y, op_ch, COLOR_EXPR);
        expr_x -= 16;
        draw_number_small(expr_x, expr_y, expr_val, COLOR_EXPR);
    }

    draw_number_large(x + w - padding - 20, y + padding + 45, display_val);

    let btn_y_start = y + display_h + padding + 10;

    let buttons: [[(&[u8], u32); 4]; 5] = [
        [(b"AC", COLOR_BTN_FUNC), (b"+/-", COLOR_BTN_FUNC), (b"%", COLOR_BTN_FUNC), (b"\xf7", COLOR_BTN_OP)],
        [(b"1", COLOR_BTN_NUM), (b"2", COLOR_BTN_NUM), (b"3", COLOR_BTN_NUM), (b"\xd7", COLOR_BTN_OP)],
        [(b"4", COLOR_BTN_NUM), (b"5", COLOR_BTN_NUM), (b"6", COLOR_BTN_NUM), (b"-", COLOR_BTN_OP)],
        [(b"7", COLOR_BTN_NUM), (b"8", COLOR_BTN_NUM), (b"9", COLOR_BTN_NUM), (b"+", COLOR_BTN_OP)],
        [(b".", COLOR_BTN_NUM), (b"0", COLOR_BTN_NUM), (b"00", COLOR_BTN_NUM), (b"=", COLOR_BTN_EQUALS)],
    ];

    for (row, btns) in buttons.iter().enumerate() {
        for (col, (label, color)) in btns.iter().enumerate() {
            let bx = x + padding + (col as u32) * (btn_w + btn_gap);
            let by = btn_y_start + (row as u32) * (btn_h + btn_gap);

            fill_rounded_rect(bx, by, btn_w, btn_h, 6, *color);

            let text_len = label.len() as u32;
            let text_w = text_len * 10;
            let text_x = bx + (btn_w - text_w) / 2;
            let text_y = by + (btn_h - 16) / 2;

            for (i, &ch) in label.iter().enumerate() {
                draw_char(text_x + (i as u32) * 10, text_y, ch, COLOR_TEXT_WHITE);
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

fn draw_clock_icon(x: u32, y: u32) {
    let color = 0xFF6E7A88;
    for dy in 0..12u32 {
        for dx in 0..12u32 {
            let dist_sq = (dx as i32 - 5) * (dx as i32 - 5) + (dy as i32 - 5) * (dy as i32 - 5);
            if dist_sq >= 16 && dist_sq <= 25 {
                put_pixel(x + dx, y + dy, color);
            }
        }
    }
    fill_rect(x + 5, y + 3, 1, 4, color);
    fill_rect(x + 5, y + 5, 3, 1, color);
}

fn draw_number_large(right_x: u32, y: u32, mut value: i64) {
    let is_negative = value < 0;
    if is_negative {
        value = -value;
    }

    let integer_part = value / 100;
    let decimal_part = (value % 100) as u32;

    let mut digits = [0u8; 24];
    let mut count = 0usize;

    let show_decimals = decimal_part != 0;
    if show_decimals {
        digits[count] = b'0' + (decimal_part % 10) as u8;
        count += 1;
        digits[count] = b'0' + (decimal_part / 10) as u8;
        count += 1;
        digits[count] = b'.';
        count += 1;
    }

    let mut int_val = integer_part;
    if int_val == 0 {
        digits[count] = b'0';
        count += 1;
    } else {
        let mut digit_count = 0;
        while int_val > 0 && count < 20 {
            if digit_count > 0 && digit_count % 3 == 0 {
                digits[count] = b',';
                count += 1;
            }
            digits[count] = b'0' + (int_val % 10) as u8;
            int_val /= 10;
            count += 1;
            digit_count += 1;
        }
    }

    let mut draw_x = right_x;
    let char_w = 18u32;

    for i in 0..count {
        if digits[i] == b',' {
            draw_char(draw_x, y, b',', COLOR_TEXT_WHITE);
            draw_x = draw_x.saturating_sub(8);
        } else if digits[i] == b'.' {
            draw_char(draw_x, y, b'.', COLOR_TEXT_WHITE);
            draw_x = draw_x.saturating_sub(8);
        } else {
            draw_char(draw_x, y, digits[i], COLOR_TEXT_WHITE);
            draw_x = draw_x.saturating_sub(char_w);
        }
    }

    if is_negative {
        draw_char(draw_x, y, b'-', COLOR_TEXT_WHITE);
    }
}

fn draw_number_small(right_x: u32, y: u32, mut value: i64, color: u32) -> u32 {
    let is_negative = value < 0;
    if is_negative {
        value = -value;
    }

    let integer_part = value / 100;
    let decimal_part = (value % 100) as u32;

    let mut digits = [0u8; 20];
    let mut count = 0usize;

    let show_decimals = decimal_part != 0;
    if show_decimals {
        digits[count] = b'0' + (decimal_part % 10) as u8;
        count += 1;
        digits[count] = b'0' + (decimal_part / 10) as u8;
        count += 1;
        digits[count] = b'.';
        count += 1;
    }

    let mut int_val = integer_part;
    if int_val == 0 {
        digits[count] = b'0';
        count += 1;
    } else {
        while int_val > 0 && count < 18 {
            digits[count] = b'0' + (int_val % 10) as u8;
            int_val /= 10;
            count += 1;
        }
    }

    let mut draw_x = right_x;
    for i in 0..count {
        if digits[i] == b'.' {
            draw_char(draw_x, y, b'.', color);
            draw_x = draw_x.saturating_sub(6);
        } else {
            draw_char(draw_x, y, digits[i], color);
            draw_x = draw_x.saturating_sub(10);
        }
    }

    if is_negative {
        draw_char(draw_x, y, b'-', color);
        draw_x = draw_x.saturating_sub(10);
    }

    draw_x
}
