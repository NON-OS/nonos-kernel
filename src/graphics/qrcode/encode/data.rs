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

use super::types::{QrCode, QR_SIZE};
use alloc::vec::Vec;

pub(super) fn is_reserved(x: usize, y: usize) -> bool {
    if x < 9 && y < 9 {
        return true;
    }
    if x >= 16 && y < 9 {
        return true;
    }
    if x < 9 && y >= 16 {
        return true;
    }
    if x == 6 || y == 6 {
        return true;
    }
    if x >= 16 && x <= 20 && y >= 16 && y <= 20 {
        return true;
    }
    if x == 8 && y >= 17 {
        return true;
    }
    if y == 8 && x >= 17 {
        return true;
    }
    false
}

pub(super) fn place_data(qr: &mut QrCode, data: &[u8]) {
    let mut bits = Vec::new();
    for &byte in data {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    let mut bit_idx = 0;
    let mut x = QR_SIZE as i32 - 1;
    let mut upward = true;
    while x > 0 {
        if x == 6 {
            x -= 1;
        }
        let col_pair = [x, x - 1];
        if upward {
            for y in (0..QR_SIZE as i32).rev() {
                for &cx in &col_pair {
                    if cx >= 0 && !is_reserved(cx as usize, y as usize) {
                        if bit_idx < bits.len() {
                            qr.modules[y as usize][cx as usize] = bits[bit_idx];
                            bit_idx += 1;
                        }
                    }
                }
            }
        } else {
            for y in 0..QR_SIZE as i32 {
                for &cx in &col_pair {
                    if cx >= 0 && !is_reserved(cx as usize, y as usize) {
                        if bit_idx < bits.len() {
                            qr.modules[y as usize][cx as usize] = bits[bit_idx];
                            bit_idx += 1;
                        }
                    }
                }
            }
        }
        x -= 2;
        upward = !upward;
    }
}
