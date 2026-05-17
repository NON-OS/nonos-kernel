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

use crate::calc::state::State;

const DIGIT_LIMIT: i64 = 999_999_999_99; // 9,999,999,999.99 displayed

pub fn input_digit(state: &mut State, digit: u8) {
    if state.error {
        return;
    }
    if state.new_input {
        state.display = (digit as i64) * 100;
        state.new_input = false;
        state.decimal_pos = 0;
        return;
    }
    let sign = if state.display < 0 { -1 } else { 1 };
    let mag = state.display.saturating_abs();
    let next = match state.decimal_pos {
        0 => {
            let int_part = mag / 100;
            let dec_part = mag % 100;
            int_part.saturating_mul(10).saturating_add(digit as i64).saturating_mul(100) + dec_part
        }
        1 => mag.saturating_add((digit as i64) * 10),
        2 => mag.saturating_add(digit as i64),
        _ => mag,
    };
    let bounded = if next > DIGIT_LIMIT { DIGIT_LIMIT } else { next };
    state.display = sign * bounded;
    if state.decimal_pos >= 1 && state.decimal_pos < 2 {
        state.decimal_pos += 1;
    }
}
