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

use core::sync::atomic::{compiler_fence, Ordering};
use super::types::CtVerifyResult;

#[inline(never)]
pub fn ct_compare(a: &[u8], b: &[u8]) -> bool {
    let len_a = a.len();
    let len_b = b.len();

    let mut result: u8 = (len_a ^ len_b) as u8;
    result |= ((len_a ^ len_b) >> 8) as u8;
    result |= ((len_a ^ len_b) >> 16) as u8;
    result |= ((len_a ^ len_b) >> 24) as u8;

    let min_len = if len_a < len_b { len_a } else { len_b };

    for i in 0..min_len {
        result |= a[i] ^ b[i];
    }

    compiler_fence(Ordering::SeqCst);

    ct_is_zero(result)
}

#[inline(never)]
pub fn ct_verify(a: &[u8], b: &[u8]) -> CtVerifyResult {
    if ct_compare(a, b) {
        CtVerifyResult::Equal
    } else {
        CtVerifyResult::NotEqual
    }
}

#[inline(always)]
pub fn ct_is_zero(x: u8) -> bool {
    let v = x | x.wrapping_sub(1);
    (v >> 7) == 0
}

#[inline(always)]
pub fn ct_is_zero_u32(x: u32) -> bool {
    let v = x | x.wrapping_sub(1);
    (v >> 31) == 0
}

#[inline(always)]
pub fn ct_is_zero_u64(x: u64) -> bool {
    let v = x | x.wrapping_sub(1);
    (v >> 63) == 0
}

#[inline(always)]
pub fn ct_select_u8(condition: u8, a: u8, b: u8) -> u8 {
    let mask = 0u8.wrapping_sub(condition);
    b ^ (mask & (a ^ b))
}

#[inline(always)]
pub fn ct_select_u32(condition: u32, a: u32, b: u32) -> u32 {
    let mask = 0u32.wrapping_sub(condition);
    b ^ (mask & (a ^ b))
}

#[inline(always)]
pub fn ct_select_u64(condition: u64, a: u64, b: u64) -> u64 {
    let mask = 0u64.wrapping_sub(condition);
    b ^ (mask & (a ^ b))
}

#[inline(never)]
pub fn ct_select_slice(condition: u8, dst: &mut [u8], src: &[u8]) {
    debug_assert_eq!(dst.len(), src.len());

    let mask = 0u8.wrapping_sub(condition);

    for i in 0..dst.len() {
        dst[i] ^= mask & (dst[i] ^ src[i]);
    }

    compiler_fence(Ordering::SeqCst);
}

#[inline(never)]
pub fn ct_swap_slices(condition: u8, a: &mut [u8], b: &mut [u8]) {
    debug_assert_eq!(a.len(), b.len());

    let mask = 0u8.wrapping_sub(condition);

    for i in 0..a.len() {
        let diff = mask & (a[i] ^ b[i]);
        a[i] ^= diff;
        b[i] ^= diff;
    }

    compiler_fence(Ordering::SeqCst);
}
