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

pub fn apply_mask(qr: &mut QrCode, pattern: u8) {
    for y in 0..SIZE {
        for x in 0..SIZE {
            if is_reserved(x, y) {
                continue;
            }
            let invert = match pattern {
                0 => (x + y) % 2 == 0,
                1 => y % 2 == 0,
                2 => x % 3 == 0,
                3 => (x + y) % 3 == 0,
                4 => (y / 2 + x / 3) % 2 == 0,
                5 => (x * y) % 2 + (x * y) % 3 == 0,
                6 => ((x * y) % 2 + (x * y) % 3) % 2 == 0,
                7 => ((x + y) % 2 + (x * y) % 3) % 2 == 0,
                _ => false,
            };
            if invert {
                qr.modules[y][x] = !qr.modules[y][x];
            }
        }
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
