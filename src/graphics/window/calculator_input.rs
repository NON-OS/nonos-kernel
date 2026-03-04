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

use core::sync::atomic::Ordering;
use super::state::TITLE_BAR_HEIGHT;
use super::calculator::{
    CALC_DISPLAY, CALC_OPERAND, CALC_OPERATOR, CALC_NEW_INPUT,
    CALC_EXPR_OP, CALC_EXPR_VAL, CALC_DECIMAL_POS,
};

pub(super) fn handle_calculator_click(win_x: u32, win_y: u32, click_x: i32, click_y: i32) -> bool {
    let content_y = win_y + TITLE_BAR_HEIGHT;
    let w = 280u32;
    let h = 380u32;
    let padding = 12u32;
    let display_h = 80u32;
    let btn_rows = 5u32;
    let btn_cols = 4u32;
    let btn_gap = 8u32;
    let btn_area_h = h - TITLE_BAR_HEIGHT - display_h - padding * 2 - 10;
    let btn_h = (btn_area_h - btn_gap * (btn_rows - 1)) / btn_rows;
    let btn_w = (w - padding * 2 - btn_gap * (btn_cols - 1)) / btn_cols;
    let btn_y_start = content_y + display_h + padding + 10;

    let rel_x = click_x - win_x as i32 - padding as i32;
    let rel_y = click_y - btn_y_start as i32;

    if rel_x < 0 || rel_y < 0 {
        return false;
    }

    let col = rel_x as u32 / (btn_w + btn_gap);
    let row = rel_y as u32 / (btn_h + btn_gap);

    if col >= btn_cols || row >= btn_rows {
        return false;
    }

    let in_btn_x = rel_x as u32 % (btn_w + btn_gap) < btn_w;
    let in_btn_y = rel_y as u32 % (btn_h + btn_gap) < btn_h;

    if !in_btn_x || !in_btn_y {
        return false;
    }

    let button_char = match (row, col) {
        (0, 0) => b'C',
        (0, 1) => b'N',
        (0, 2) => b'%',
        (0, 3) => b'/',
        (1, 0) => b'1',
        (1, 1) => b'2',
        (1, 2) => b'3',
        (1, 3) => b'*',
        (2, 0) => b'4',
        (2, 1) => b'5',
        (2, 2) => b'6',
        (2, 3) => b'-',
        (3, 0) => b'7',
        (3, 1) => b'8',
        (3, 2) => b'9',
        (3, 3) => b'+',
        (4, 0) => b'.',
        (4, 1) => b'0',
        (4, 2) => b'D',
        (4, 3) => b'=',
        _ => return false,
    };

    process_calc_input(button_char);
    true
}

fn process_calc_input(ch: u8) {
    let current = CALC_DISPLAY.load(Ordering::Relaxed);
    let decimal_pos = CALC_DECIMAL_POS.load(Ordering::Relaxed);

    match ch {
        b'0'..=b'9' => {
            let digit = (ch - b'0') as i64;
            if CALC_NEW_INPUT.load(Ordering::Relaxed) {
                CALC_DISPLAY.store(digit * 100, Ordering::Relaxed);
                CALC_NEW_INPUT.store(false, Ordering::Relaxed);
                CALC_DECIMAL_POS.store(0, Ordering::Relaxed);
            } else if decimal_pos > 0 {
                if decimal_pos == 1 {
                    let sign = if current < 0 { -1 } else { 1 };
                    let new_val = current + digit * 10 * sign;
                    CALC_DISPLAY.store(new_val, Ordering::Relaxed);
                    CALC_DECIMAL_POS.store(2, Ordering::Relaxed);
                } else if decimal_pos == 2 {
                    let sign = if current < 0 { -1 } else { 1 };
                    let new_val = current + digit * sign;
                    CALC_DISPLAY.store(new_val, Ordering::Relaxed);
                    CALC_DECIMAL_POS.store(3, Ordering::Relaxed);
                }
            } else if current.abs() < 99999999999900 {
                let sign = if current < 0 { -1 } else { 1 };
                CALC_DISPLAY.store(current * 10 + digit * 100 * sign, Ordering::Relaxed);
            }
        }
        b'.' => {
            if CALC_NEW_INPUT.load(Ordering::Relaxed) {
                CALC_DISPLAY.store(0, Ordering::Relaxed);
                CALC_NEW_INPUT.store(false, Ordering::Relaxed);
            }
            if decimal_pos == 0 {
                CALC_DECIMAL_POS.store(1, Ordering::Relaxed);
            }
        }
        b'D' => {
            if CALC_NEW_INPUT.load(Ordering::Relaxed) {
                CALC_DISPLAY.store(0, Ordering::Relaxed);
                CALC_NEW_INPUT.store(false, Ordering::Relaxed);
                CALC_DECIMAL_POS.store(0, Ordering::Relaxed);
            } else if decimal_pos == 0 && current.abs() < 999999999900 {
                CALC_DISPLAY.store(current * 100, Ordering::Relaxed);
            }
        }
        b'C' => {
            CALC_DISPLAY.store(0, Ordering::Relaxed);
            CALC_OPERAND.store(0, Ordering::Relaxed);
            CALC_OPERATOR.store(0, Ordering::Relaxed);
            CALC_EXPR_OP.store(0, Ordering::Relaxed);
            CALC_EXPR_VAL.store(0, Ordering::Relaxed);
            CALC_DECIMAL_POS.store(0, Ordering::Relaxed);
            CALC_NEW_INPUT.store(true, Ordering::Relaxed);
        }
        b'N' => {
            CALC_DISPLAY.store(-current, Ordering::Relaxed);
        }
        b'+' | b'-' | b'*' | b'/' => {
            CALC_OPERAND.store(current, Ordering::Relaxed);
            CALC_EXPR_VAL.store(current, Ordering::Relaxed);
            let op = match ch {
                b'+' => 1,
                b'-' => 2,
                b'*' => 3,
                b'/' => 4,
                _ => 0,
            };
            CALC_OPERATOR.store(op, Ordering::Relaxed);
            CALC_EXPR_OP.store(op, Ordering::Relaxed);
            CALC_DECIMAL_POS.store(0, Ordering::Relaxed);
            CALC_NEW_INPUT.store(true, Ordering::Relaxed);
        }
        b'=' => {
            let operand = CALC_OPERAND.load(Ordering::Relaxed);
            let operator = CALC_OPERATOR.load(Ordering::Relaxed);

            let result = match operator {
                1 => operand.saturating_add(current),
                2 => operand.saturating_sub(current),
                3 => (operand * current) / 100,
                4 => if current != 0 { (operand * 100) / current } else { 0 },
                _ => current,
            };

            CALC_DISPLAY.store(result, Ordering::Relaxed);
            CALC_OPERATOR.store(0, Ordering::Relaxed);
            CALC_EXPR_OP.store(0, Ordering::Relaxed);
            CALC_DECIMAL_POS.store(0, Ordering::Relaxed);
            CALC_NEW_INPUT.store(true, Ordering::Relaxed);
        }
        b'%' => {
            CALC_DISPLAY.store(current / 100, Ordering::Relaxed);
        }
        _ => {}
    }
}
