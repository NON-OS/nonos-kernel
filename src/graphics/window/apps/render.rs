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

use crate::graphics::font::draw_char;

pub fn draw_string(x: u32, y: u32, text: &[u8], color: u32) {
    for (i, &ch) in text.iter().enumerate() {
        draw_char(x + (i as u32) * 8, y, ch, color);
    }
}

pub fn draw_number(x: u32, y: u32, num: u32, color: u32) -> u32 {
    let mut buf = [0u8; 10];
    let mut n = num;
    let mut i = 0;

    if n == 0 {
        draw_char(x, y, b'0', color);
        return 8;
    }

    while n > 0 && i < 10 {
        buf[9 - i] = b'0' + (n % 10) as u8;
        n /= 10;
        i += 1;
    }

    let start = 10 - i;
    for (j, &digit) in buf[start..].iter().enumerate() {
        draw_char(x + (j as u32) * 8, y, digit, color);
    }
    i as u32 * 8
}
