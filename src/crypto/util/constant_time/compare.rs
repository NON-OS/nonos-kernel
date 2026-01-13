// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use super::{compiler_fence, volatile_read};
#[inline(never)]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        let mut dummy: u8 = 0;
        for i in 0..a.len().max(b.len()) {
            let av = if i < a.len() { a[i] } else { 0 };
            let bv = if i < b.len() { b[i] } else { 0 };
            dummy |= av ^ bv;
        }
        volatile_read(&dummy);
        return false;
    }

    let mut diff: u8 = 0;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    compiler_fence();
    diff == 0
}

#[inline(never)]
pub fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    compiler_fence();
    diff == 0
}

#[inline(never)]
pub fn ct_eq_64(a: &[u8; 64], b: &[u8; 64]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..64 {
        diff |= a[i] ^ b[i];
    }
    compiler_fence();
    diff == 0
}

#[inline(never)]
pub fn ct_eq_16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    let mut diff: u8 = 0;
    for i in 0..16 {
        diff |= a[i] ^ b[i];
    }
    compiler_fence();
    diff == 0
}

#[inline(always)]
pub fn ct_lt_u64(a: u64, b: u64) -> u64 {
    let x = a ^ ((a ^ b) | (a.wrapping_sub(b) ^ b));
    x >> 63
}

#[inline(always)]
pub fn ct_gt_u64(a: u64, b: u64) -> u64 {
    ct_lt_u64(b, a)
}

#[inline(always)]
pub fn ct_eq_u64(a: u64, b: u64) -> u64 {
    let diff = a ^ b;
    let is_zero = diff | diff.wrapping_neg();
    1 ^ (is_zero >> 63)
}

#[inline(always)]
pub fn ct_is_zero_u64(x: u64) -> u64 {
    let is_nonzero = x | x.wrapping_neg();
    1 ^ (is_nonzero >> 63)
}

#[inline(always)]
pub fn ct_is_nonzero_u64(x: u64) -> u64 {
    let is_nonzero = x | x.wrapping_neg();
    is_nonzero >> 63
}
