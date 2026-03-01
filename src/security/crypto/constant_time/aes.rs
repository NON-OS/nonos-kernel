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

#[inline(never)]
pub fn sbox_ct(input: u8) -> u8 {
    let inv = gf256_inv_ct(input);

    let mut result = inv;
    result ^= inv.rotate_left(1);
    result ^= inv.rotate_left(2);
    result ^= inv.rotate_left(3);
    result ^= inv.rotate_left(4);
    result ^= 0x63;

    compiler_fence(Ordering::SeqCst);

    result
}

#[inline(always)]
fn gf256_inv_ct(x: u8) -> u8 {
    if x == 0 {
        return 0;
    }

    let x2 = gf256_mul_ct(x, x);
    let x3 = gf256_mul_ct(x2, x);
    let x6 = gf256_mul_ct(x3, x3);
    let x12 = gf256_mul_ct(x6, x6);
    let x14 = gf256_mul_ct(x12, x2);
    let x15 = gf256_mul_ct(x14, x);
    let x30 = gf256_mul_ct(x15, x15);
    let x60 = gf256_mul_ct(x30, x30);
    let x120 = gf256_mul_ct(x60, x60);
    let x126 = gf256_mul_ct(x120, x6);
    let x127 = gf256_mul_ct(x126, x);
    let x254 = gf256_mul_ct(x127, x127);

    x254
}

#[inline(always)]
fn gf256_mul_ct(a: u8, b: u8) -> u8 {
    let mut result = 0u8;
    let mut aa = a;
    let mut bb = b;

    for _ in 0..8 {
        let mask = 0u8.wrapping_sub(bb & 1);
        result ^= aa & mask;

        bb >>= 1;

        let high_bit_set = (aa >> 7) & 1;
        aa <<= 1;
        let reduce_mask = 0u8.wrapping_sub(high_bit_set);
        aa ^= 0x1B & reduce_mask;
    }

    result
}
