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

use alloc::{vec, vec::Vec};

pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut result = 0u8;
    for i in 0..a.len() {
        result |= a[i] ^ b[i];
    }
    result == 0
}

pub fn secure_memzero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        unsafe {
            core::ptr::write_volatile(byte, 0);
        }
    }
}

pub fn conditional_select(condition: bool, a: &[u8], b: &[u8]) -> Vec<u8> {
    let mask = if condition { 0xFF } else { 0x00 };
    let mut result = vec![0u8; a.len().max(b.len())];
    for i in 0..result.len() {
        let a_byte = if i < a.len() { a[i] } else { 0 };
        let b_byte = if i < b.len() { b[i] } else { 0 };
        result[i] = (mask & a_byte) | (!mask & b_byte);
    }
    result
}
