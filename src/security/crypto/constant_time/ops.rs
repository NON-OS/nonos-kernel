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
use super::core::{ct_is_zero_u32, ct_is_zero_u64, ct_select_u8, ct_select_u32};

#[inline(always)]
pub fn ct_lt_u32(a: u32, b: u32) -> u32 {
    let diff = a.wrapping_sub(b);
    (diff >> 31) & 1
}

#[inline(always)]
pub fn ct_lt_u64(a: u64, b: u64) -> u64 {
    let diff = a.wrapping_sub(b);
    (diff >> 63) & 1
}

#[inline(always)]
pub fn ct_gt_u32(a: u32, b: u32) -> u32 {
    ct_lt_u32(b, a)
}

#[inline(always)]
pub fn ct_eq_u32(a: u32, b: u32) -> u32 {
    let diff = a ^ b;
    if ct_is_zero_u32(diff) { 1 } else { 0 }
}

#[inline(always)]
pub fn ct_eq_u64(a: u64, b: u64) -> u64 {
    let diff = a ^ b;
    if ct_is_zero_u64(diff) { 1 } else { 0 }
}

#[inline(always)]
pub fn ct_min_u32(a: u32, b: u32) -> u32 {
    ct_select_u32(ct_lt_u32(a, b), a, b)
}

#[inline(always)]
pub fn ct_max_u32(a: u32, b: u32) -> u32 {
    ct_select_u32(ct_gt_u32(a, b), a, b)
}

#[inline(never)]
pub fn ct_copy_bounded(dst: &mut [u8], src: &[u8], len: usize) {
    let actual_len = ct_min_u32(len as u32, ct_min_u32(dst.len() as u32, src.len() as u32)) as usize;

    for i in 0..dst.len() {
        let in_bounds = ct_lt_u32(i as u32, actual_len as u32) as u8;
        let _mask = 0u8.wrapping_sub(in_bounds);

        let src_byte = if i < src.len() { src[i] } else { 0 };

        dst[i] = ct_select_u8(in_bounds, src_byte, dst[i]);
    }

    compiler_fence(Ordering::SeqCst);
}
