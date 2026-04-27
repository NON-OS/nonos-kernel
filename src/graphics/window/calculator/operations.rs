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

use super::history;
use super::state::*;
use core::sync::atomic::Ordering;

pub const OP_NONE: u8 = 0;
pub const OP_ADD: u8 = 1;
pub const OP_SUB: u8 = 2;
pub const OP_MUL: u8 = 3;
pub const OP_DIV: u8 = 4;

pub fn calculate(a: i64, b: i64, op: u8) -> i64 {
    match op {
        OP_ADD => a.saturating_add(b),
        OP_SUB => a.saturating_sub(b),
        OP_MUL => a.saturating_mul(b),
        OP_DIV => {
            if b != 0 {
                a / b
            } else {
                0
            }
        }
        _ => b,
    }
}

pub fn execute_operation() {
    let op = CALC_OPERATOR.load(Ordering::Relaxed);
    if op == OP_NONE {
        return;
    }
    let a = CALC_OPERAND.load(Ordering::Relaxed);
    let b = CALC_DISPLAY.load(Ordering::Relaxed);
    let result = calculate(a, b, op);
    history::add_entry(a, b, op, result);
    CALC_DISPLAY.store(result, Ordering::Relaxed);
    CALC_OPERATOR.store(OP_NONE, Ordering::Relaxed);
    CALC_NEW_INPUT.store(true, Ordering::Relaxed);
    CALC_EXPR_OP.store(OP_NONE, Ordering::Relaxed);
}

pub fn set_operator(op: u8) {
    let current_op = CALC_OPERATOR.load(Ordering::Relaxed);
    if current_op != OP_NONE && !CALC_NEW_INPUT.load(Ordering::Relaxed) {
        execute_operation();
    }
    CALC_OPERAND.store(CALC_DISPLAY.load(Ordering::Relaxed), Ordering::Relaxed);
    CALC_EXPR_VAL.store(CALC_DISPLAY.load(Ordering::Relaxed), Ordering::Relaxed);
    CALC_EXPR_OP.store(op, Ordering::Relaxed);
    CALC_OPERATOR.store(op, Ordering::Relaxed);
    CALC_NEW_INPUT.store(true, Ordering::Relaxed);
}

pub fn input_digit(digit: u8) {
    if CALC_NEW_INPUT.load(Ordering::Relaxed) {
        CALC_DISPLAY.store((digit as i64) * 100, Ordering::Relaxed);
        CALC_NEW_INPUT.store(false, Ordering::Relaxed);
        CALC_DECIMAL_POS.store(0, Ordering::Relaxed);
    } else {
        let current = CALC_DISPLAY.load(Ordering::Relaxed);
        let dec_pos = CALC_DECIMAL_POS.load(Ordering::Relaxed);
        if dec_pos > 0 && dec_pos <= 2 {
            let shift = if dec_pos == 1 { 10 } else { 1 };
            let new_val = current + (digit as i64) * shift;
            CALC_DISPLAY.store(new_val, Ordering::Relaxed);
            if dec_pos < 2 {
                CALC_DECIMAL_POS.store(dec_pos + 1, Ordering::Relaxed);
            }
        } else if dec_pos == 0 {
            let int_part = current / 100;
            let dec_part = current % 100;
            let new_int = int_part * 10 + digit as i64;
            CALC_DISPLAY.store(new_int * 100 + dec_part, Ordering::Relaxed);
        }
    }
}

pub fn clear_all() {
    CALC_DISPLAY.store(0, Ordering::Relaxed);
    CALC_OPERAND.store(0, Ordering::Relaxed);
    CALC_OPERATOR.store(OP_NONE, Ordering::Relaxed);
    CALC_NEW_INPUT.store(true, Ordering::Relaxed);
    CALC_EXPR_OP.store(OP_NONE, Ordering::Relaxed);
    CALC_DECIMAL_POS.store(0, Ordering::Relaxed);
}
