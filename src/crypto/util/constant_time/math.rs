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

use super::{ct_gt_u64, ct_is_zero_u64, ct_lt_u64, ct_select_u32, ct_select_u64};

#[inline(always)]
pub fn ct_add_u64(a: u64, b: u64) -> (u64, u64) {
    let result = a.wrapping_add(b);
    let carry = ct_lt_u64(result, a);
    (result, carry)
}

#[inline(always)]
pub fn ct_sub_u64(a: u64, b: u64) -> (u64, u64) {
    let result = a.wrapping_sub(b);
    let borrow = ct_lt_u64(a, b);
    (result, borrow)
}

#[inline(always)]
pub fn ct_mul_u64(a: u64, b: u64) -> (u64, u64) {
    let full = (a as u128) * (b as u128);
    (full as u64, (full >> 64) as u64)
}

#[inline(always)]
pub fn ct_add_overflow_u64(a: u64, b: u64) -> (u64, bool) {
    let (result, carry) = ct_add_u64(a, b);
    (result, carry != 0)
}

#[inline(always)]
pub fn ct_popcount_u64(mut x: u64) -> u32 {
    x = x - ((x >> 1) & 0x5555555555555555);
    x = (x & 0x3333333333333333) + ((x >> 2) & 0x3333333333333333);
    x = (x + (x >> 4)) & 0x0f0f0f0f0f0f0f0f;
    x = x.wrapping_mul(0x0101010101010101);
    (x >> 56) as u32
}

#[inline(always)]
pub fn ct_clz_u64(x: u64) -> u32 {
    let mut n: u32 = 0;
    let mut val = x;

    let upper_zero = ct_is_zero_u64(val >> 32);
    n = ct_select_u32(upper_zero != 0, 32, 0);
    val = ct_select_u64(upper_zero != 0, val << 32, val);

    let upper_zero = ct_is_zero_u64(val >> 48);
    n += ct_select_u32(upper_zero != 0, 16, 0);
    val = ct_select_u64(upper_zero != 0, val << 16, val);

    let upper_zero = ct_is_zero_u64(val >> 56);
    n += ct_select_u32(upper_zero != 0, 8, 0);
    val = ct_select_u64(upper_zero != 0, val << 8, val);

    let upper_zero = ct_is_zero_u64(val >> 60);
    n += ct_select_u32(upper_zero != 0, 4, 0);
    val = ct_select_u64(upper_zero != 0, val << 4, val);

    let upper_zero = ct_is_zero_u64(val >> 62);
    n += ct_select_u32(upper_zero != 0, 2, 0);
    val = ct_select_u64(upper_zero != 0, val << 2, val);

    let upper_zero = ct_is_zero_u64(val >> 63);
    n += ct_select_u32(upper_zero != 0, 1, 0);
    val = ct_select_u64(upper_zero != 0, val << 1, val);

    let final_zero = ct_is_zero_u64(val >> 63);
    n += ct_select_u32(final_zero != 0, 1, 0);

    n
}

#[inline(always)]
pub fn ct_bswap_u64(x: u64) -> u64 {
    let x = ((x >> 8) & 0x00FF00FF00FF00FF) | ((x & 0x00FF00FF00FF00FF) << 8);
    let x = ((x >> 16) & 0x0000FFFF0000FFFF) | ((x & 0x0000FFFF0000FFFF) << 16);
    (x >> 32) | (x << 32)
}

#[inline(always)]
pub fn ct_bswap_u32(x: u32) -> u32 {
    let x = ((x >> 8) & 0x00FF00FF) | ((x & 0x00FF00FF) << 8);
    (x >> 16) | (x << 16)
}

#[inline(always)]
pub fn ct_mod_u64(a: u64, m: u64) -> u64 {
    let mut result = a;
    let should_sub = ct_gt_u64(result, m.wrapping_sub(1));
    result = ct_select_u64(should_sub != 0, result.wrapping_sub(m), result);
    result
}

#[inline(always)]
pub fn ct_conditional_negate(x: u64, m: u64, cond: bool) -> u64 {
    let negated = m.wrapping_sub(x);
    ct_select_u64(cond, negated, x)
}
