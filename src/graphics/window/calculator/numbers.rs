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

use crate::graphics::design_system::colors::TEXT_PRIMARY;
use crate::graphics::font::draw_char;

pub(super) fn draw_number_large(right_x: u32, y: u32, mut value: i64) {
    let is_neg = value < 0;
    if is_neg {
        value = -value;
    }
    let int_part = value / 100;
    let dec_part = (value % 100) as u32;
    let mut digits = [0u8; 24];
    let mut count = 0usize;

    if dec_part != 0 {
        digits[count] = b'0' + (dec_part % 10) as u8;
        count += 1;
        digits[count] = b'0' + (dec_part / 10) as u8;
        count += 1;
        digits[count] = b'.';
        count += 1;
    }

    let mut v = int_part;
    if v == 0 {
        digits[count] = b'0';
        count += 1;
    } else {
        let mut dc = 0;
        while v > 0 && count < 20 {
            if dc > 0 && dc % 3 == 0 {
                digits[count] = b',';
                count += 1;
            }
            digits[count] = b'0' + (v % 10) as u8;
            v /= 10;
            count += 1;
            dc += 1;
        }
    }

    let mut dx = right_x;
    for i in 0..count {
        let w = if digits[i] == b',' || digits[i] == b'.' { 8 } else { 18 };
        draw_char(dx, y, digits[i], TEXT_PRIMARY);
        dx = dx.saturating_sub(w);
    }
    if is_neg {
        draw_char(dx, y, b'-', TEXT_PRIMARY);
    }
}

pub(super) fn draw_number_small(right_x: u32, y: u32, mut value: i64, color: u32) -> u32 {
    let is_neg = value < 0;
    if is_neg {
        value = -value;
    }
    let int_part = value / 100;
    let dec_part = (value % 100) as u32;
    let mut digits = [0u8; 20];
    let mut count = 0usize;

    if dec_part != 0 {
        digits[count] = b'0' + (dec_part % 10) as u8;
        count += 1;
        digits[count] = b'0' + (dec_part / 10) as u8;
        count += 1;
        digits[count] = b'.';
        count += 1;
    }

    let mut v = int_part;
    if v == 0 {
        digits[count] = b'0';
        count += 1;
    } else {
        while v > 0 && count < 18 {
            digits[count] = b'0' + (v % 10) as u8;
            v /= 10;
            count += 1;
        }
    }

    let mut dx = right_x;
    for i in 0..count {
        let w = if digits[i] == b'.' { 6 } else { 10 };
        draw_char(dx, y, digits[i], color);
        dx = dx.saturating_sub(w);
    }
    if is_neg {
        draw_char(dx, y, b'-', color);
        dx = dx.saturating_sub(10);
    }
    dx
}
