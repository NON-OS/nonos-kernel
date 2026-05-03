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

use super::encode::{QrCode, SIZE};

pub fn place_data(qr: &mut QrCode, data: &[u8; 26]) {
    let mut bit_idx = 0;
    let mut x = SIZE as i32 - 1;
    let mut upward = true;
    while x >= 0 {
        if x == 6 {
            x -= 1;
        }
        for row in 0..SIZE {
            let y = if upward { SIZE - 1 - row } else { row };
            for dx in [0i32, -1] {
                let col = (x + dx) as usize;
                if col < SIZE && !is_reserved(col, y) && bit_idx < 208 {
                    let byte_idx = bit_idx / 8;
                    let bit_pos = 7 - (bit_idx % 8);
                    qr.modules[y][col] = (data[byte_idx] >> bit_pos) & 1 == 1;
                    bit_idx += 1;
                }
            }
        }
        x -= 2;
        upward = !upward;
    }
}

fn is_reserved(x: usize, y: usize) -> bool {
    if x < 9 && y < 9 {
        return true;
    }
    if x >= SIZE - 8 && y < 9 {
        return true;
    }
    if x < 9 && y >= SIZE - 8 {
        return true;
    }
    if x == 6 || y == 6 {
        return true;
    }
    false
}
