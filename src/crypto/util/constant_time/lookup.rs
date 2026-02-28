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

use super::barriers::compiler_fence;

#[inline(always)]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let diff = a ^ b;
    let is_zero = diff | diff.wrapping_neg();
    1 ^ ((is_zero >> 7) & 1)
}

#[inline(always)]
fn ct_eq_usize(a: usize, b: usize) -> u32 {
    let diff = a ^ b;
    let is_zero = (diff | diff.wrapping_neg()) as u64;
    1 ^ (((is_zero >> 63) & 1) as u32)
}

#[inline(never)]
pub fn ct_lookup_u8(table: &[u8; 256], index: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..256 {
        let eq = ct_eq_u8(i as u8, index);
        let mask = (-(eq as i8)) as u8;
        result |= mask & table[i];
    }
    compiler_fence();
    result
}

#[inline(never)]
pub fn ct_lookup_u8_16(table: &[u8; 16], index: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..16 {
        let eq = ct_eq_u8(i as u8, index);
        let mask = (-(eq as i8)) as u8;
        result |= mask & table[i];
    }
    compiler_fence();
    result
}

#[inline(never)]
pub fn ct_lookup_u32(table: &[u32], index: usize) -> u32 {
    let mut result: u32 = 0;
    for i in 0..table.len() {
        let eq = ct_eq_usize(i, index);
        let mask = 0u32.wrapping_sub(eq);
        result |= mask & table[i];
    }
    compiler_fence();
    result
}

#[inline(never)]
pub fn ct_is_zero_slice(data: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for &byte in data {
        acc |= byte;
    }
    compiler_fence();
    acc == 0
}

#[inline(never)]
pub fn ct_is_nonzero_slice(data: &[u8]) -> bool {
    !ct_is_zero_slice(data)
}
