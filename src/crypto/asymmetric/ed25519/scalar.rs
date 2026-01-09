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

use crate::crypto::asymmetric::ed25519::field::{load3, load4};

pub(crate) const L: [u8; 32] = [
    0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58, 0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
];

#[inline]
pub(crate) fn clamp_scalar(a: &mut [u8; 32]) {
    a[0] &= 248;
    a[31] &= 63;
    a[31] |= 64;
}

pub(crate) fn sc_reduce_mod_l(s: &mut [u8; 64]) -> [u8; 32] {
    let mut a = [0i64; 24];
    a[0] = (2097151 & load3(&s[0..])) as i64;
    a[1] = (2097151 & (load4(&s[2..]) >> 5)) as i64;
    a[2] = (2097151 & (load3(&s[5..]) >> 2)) as i64;
    a[3] = (2097151 & (load4(&s[7..]) >> 7)) as i64;
    a[4] = (2097151 & (load4(&s[10..]) >> 4)) as i64;
    a[5] = (2097151 & (load3(&s[13..]) >> 1)) as i64;
    a[6] = (2097151 & (load4(&s[15..]) >> 6)) as i64;
    a[7] = (2097151 & (load3(&s[18..]) >> 3)) as i64;
    a[8] = (2097151 & load3(&s[21..])) as i64;
    a[9] = (2097151 & (load4(&s[23..]) >> 5)) as i64;
    a[10] = (2097151 & (load3(&s[26..]) >> 2)) as i64;
    a[11] = (2097151 & (load4(&s[28..]) >> 7)) as i64;
    a[12] = (2097151 & (load4(&s[31..]) >> 4)) as i64;
    a[13] = (2097151 & (load3(&s[34..]) >> 1)) as i64;
    a[14] = (2097151 & (load4(&s[36..]) >> 6)) as i64;
    a[15] = (2097151 & (load3(&s[39..]) >> 3)) as i64;
    a[16] = (2097151 & load3(&s[42..])) as i64;
    a[17] = (2097151 & (load4(&s[44..]) >> 5)) as i64;
    a[18] = (2097151 & (load3(&s[47..]) >> 2)) as i64;
    a[19] = (2097151 & (load4(&s[49..]) >> 7)) as i64;
    a[20] = (2097151 & (load4(&s[52..]) >> 4)) as i64;
    a[21] = (2097151 & (load3(&s[55..]) >> 1)) as i64;
    a[22] = (2097151 & (load4(&s[57..]) >> 6)) as i64;
    a[23] = (load4(&s[60..]) >> 3) as i64;

    a[11] += a[23] * 666643;
    a[12] += a[23] * 470296;
    a[13] += a[23] * 654183;
    a[14] -= a[23] * 997805;
    a[15] += a[23] * 136657;
    a[16] -= a[23] * 683901;

    a[10] += a[22] * 666643;
    a[11] += a[22] * 470296;
    a[12] += a[22] * 654183;
    a[13] -= a[22] * 997805;
    a[14] += a[22] * 136657;
    a[15] -= a[22] * 683901;

    a[9] += a[21] * 666643;
    a[10] += a[21] * 470296;
    a[11] += a[21] * 654183;
    a[12] -= a[21] * 997805;
    a[13] += a[21] * 136657;
    a[14] -= a[21] * 683901;

    a[8] += a[20] * 666643;
    a[9] += a[20] * 470296;
    a[10] += a[20] * 654183;
    a[11] -= a[20] * 997805;
    a[12] += a[20] * 136657;
    a[13] -= a[20] * 683901;

    a[7] += a[19] * 666643;
    a[8] += a[19] * 470296;
    a[9] += a[19] * 654183;
    a[10] -= a[19] * 997805;
    a[11] += a[19] * 136657;
    a[12] -= a[19] * 683901;

    a[6] += a[18] * 666643;
    a[7] += a[18] * 470296;
    a[8] += a[18] * 654183;
    a[9] -= a[18] * 997805;
    a[10] += a[18] * 136657;
    a[11] -= a[18] * 683901;

    let mut carry: i64;
    carry = (a[6] + (1 << 20)) >> 21;
    a[7] += carry;
    a[6] -= carry << 21;
    carry = (a[8] + (1 << 20)) >> 21;
    a[9] += carry;
    a[8] -= carry << 21;
    carry = (a[10] + (1 << 20)) >> 21;
    a[11] += carry;
    a[10] -= carry << 21;
    carry = (a[12] + (1 << 20)) >> 21;
    a[13] += carry;
    a[12] -= carry << 21;
    carry = (a[14] + (1 << 20)) >> 21;
    a[15] += carry;
    a[14] -= carry << 21;
    carry = (a[16] + (1 << 20)) >> 21;
    a[17] += carry;
    a[16] -= carry << 21;

    carry = (a[7] + (1 << 20)) >> 21;
    a[8] += carry;
    a[7] -= carry << 21;
    carry = (a[9] + (1 << 20)) >> 21;
    a[10] += carry;
    a[9] -= carry << 21;
    carry = (a[11] + (1 << 20)) >> 21;
    a[12] += carry;
    a[11] -= carry << 21;
    carry = (a[13] + (1 << 20)) >> 21;
    a[14] += carry;
    a[13] -= carry << 21;
    carry = (a[15] + (1 << 20)) >> 21;
    a[16] += carry;
    a[15] -= carry << 21;

    a[5] += a[17] * 666643;
    a[6] += a[17] * 470296;
    a[7] += a[17] * 654183;
    a[8] -= a[17] * 997805;
    a[9] += a[17] * 136657;
    a[10] -= a[17] * 683901;

    a[4] += a[16] * 666643;
    a[5] += a[16] * 470296;
    a[6] += a[16] * 654183;
    a[7] -= a[16] * 997805;
    a[8] += a[16] * 136657;
    a[9] -= a[16] * 683901;

    a[3] += a[15] * 666643;
    a[4] += a[15] * 470296;
    a[5] += a[15] * 654183;
    a[6] -= a[15] * 997805;
    a[7] += a[15] * 136657;
    a[8] -= a[15] * 683901;

    a[2] += a[14] * 666643;
    a[3] += a[14] * 470296;
    a[4] += a[14] * 654183;
    a[5] -= a[14] * 997805;
    a[6] += a[14] * 136657;
    a[7] -= a[14] * 683901;

    a[1] += a[13] * 666643;
    a[2] += a[13] * 470296;
    a[3] += a[13] * 654183;
    a[4] -= a[13] * 997805;
    a[5] += a[13] * 136657;
    a[6] -= a[13] * 683901;

    a[0] += a[12] * 666643;
    a[1] += a[12] * 470296;
    a[2] += a[12] * 654183;
    a[3] -= a[12] * 997805;
    a[4] += a[12] * 136657;
    a[5] -= a[12] * 683901;

    carry = (a[0] + (1 << 20)) >> 21;
    a[1] += carry;
    a[0] -= carry << 21;
    carry = (a[2] + (1 << 20)) >> 21;
    a[3] += carry;
    a[2] -= carry << 21;
    carry = (a[4] + (1 << 20)) >> 21;
    a[5] += carry;
    a[4] -= carry << 21;
    carry = (a[6] + (1 << 20)) >> 21;
    a[7] += carry;
    a[6] -= carry << 21;
    carry = (a[8] + (1 << 20)) >> 21;
    a[9] += carry;
    a[8] -= carry << 21;
    carry = (a[10] + (1 << 20)) >> 21;
    a[11] += carry;
    a[10] -= carry << 21;

    carry = (a[1] + (1 << 20)) >> 21;
    a[2] += carry;
    a[1] -= carry << 21;
    carry = (a[3] + (1 << 20)) >> 21;
    a[4] += carry;
    a[3] -= carry << 21;
    carry = (a[5] + (1 << 20)) >> 21;
    a[6] += carry;
    a[5] -= carry << 21;
    carry = (a[7] + (1 << 20)) >> 21;
    a[8] += carry;
    a[7] -= carry << 21;
    carry = (a[9] + (1 << 20)) >> 21;
    a[10] += carry;
    a[9] -= carry << 21;
    carry = (a[11] + (1 << 20)) >> 21;
    a[12] = carry;
    a[11] -= carry << 21;

    a[0] += a[12] * 666643;
    a[1] += a[12] * 470296;
    a[2] += a[12] * 654183;
    a[3] -= a[12] * 997805;
    a[4] += a[12] * 136657;
    a[5] -= a[12] * 683901;

    carry = a[0] >> 21;
    a[1] += carry;
    a[0] -= carry << 21;
    carry = a[1] >> 21;
    a[2] += carry;
    a[1] -= carry << 21;
    carry = a[2] >> 21;
    a[3] += carry;
    a[2] -= carry << 21;
    carry = a[3] >> 21;
    a[4] += carry;
    a[3] -= carry << 21;
    carry = a[4] >> 21;
    a[5] += carry;
    a[4] -= carry << 21;
    carry = a[5] >> 21;
    a[6] += carry;
    a[5] -= carry << 21;
    carry = a[6] >> 21;
    a[7] += carry;
    a[6] -= carry << 21;
    carry = a[7] >> 21;
    a[8] += carry;
    a[7] -= carry << 21;
    carry = a[8] >> 21;
    a[9] += carry;
    a[8] -= carry << 21;
    carry = a[9] >> 21;
    a[10] += carry;
    a[9] -= carry << 21;
    carry = a[10] >> 21;
    a[11] += carry;
    a[10] -= carry << 21;

    carry = a[11] >> 21;
    if carry != 0 {
        a[0] += carry * 666643;
        a[1] += carry * 470296;
        a[2] += carry * 654183;
        a[3] -= carry * 997805;
        a[4] += carry * 136657;
        a[5] -= carry * 683901;
        a[11] -= carry << 21;

        carry = a[0] >> 21;
        a[1] += carry;
        a[0] -= carry << 21;
        carry = a[1] >> 21;
        a[2] += carry;
        a[1] -= carry << 21;
        carry = a[2] >> 21;
        a[3] += carry;
        a[2] -= carry << 21;
        carry = a[3] >> 21;
        a[4] += carry;
        a[3] -= carry << 21;
        carry = a[4] >> 21;
        a[5] += carry;
        a[4] -= carry << 21;
        carry = a[5] >> 21;
        a[6] += carry;
        a[5] -= carry << 21;
        carry = a[6] >> 21;
        a[7] += carry;
        a[6] -= carry << 21;
        carry = a[7] >> 21;
        a[8] += carry;
        a[7] -= carry << 21;
        carry = a[8] >> 21;
        a[9] += carry;
        a[8] -= carry << 21;
        carry = a[9] >> 21;
        a[10] += carry;
        a[9] -= carry << 21;
        carry = a[10] >> 21;
        a[11] += carry;
        a[10] -= carry << 21;
    }

    #[cfg(debug_assertions)]
    for i in 0..12 {
        debug_assert!(a[i] >= 0, "Negative limb a[{}] = {}", i, a[i]);
        debug_assert!(a[i] < (1 << 22), "Limb a[{}] = {} too large", i, a[i]);
    }

    let mut out = [0u8; 32];
    out[0] = a[0] as u8;
    out[1] = (a[0] >> 8) as u8;
    out[2] = ((a[0] >> 16) | (a[1] << 5)) as u8;
    out[3] = (a[1] >> 3) as u8;
    out[4] = (a[1] >> 11) as u8;
    out[5] = ((a[1] >> 19) | (a[2] << 2)) as u8;
    out[6] = (a[2] >> 6) as u8;
    out[7] = ((a[2] >> 14) | (a[3] << 7)) as u8;
    out[8] = (a[3] >> 1) as u8;
    out[9] = (a[3] >> 9) as u8;
    out[10] = ((a[3] >> 17) | (a[4] << 4)) as u8;
    out[11] = (a[4] >> 4) as u8;
    out[12] = (a[4] >> 12) as u8;
    out[13] = ((a[4] >> 20) | (a[5] << 1)) as u8;
    out[14] = (a[5] >> 7) as u8;
    out[15] = ((a[5] >> 15) | (a[6] << 6)) as u8;
    out[16] = (a[6] >> 2) as u8;
    out[17] = (a[6] >> 10) as u8;
    out[18] = ((a[6] >> 18) | (a[7] << 3)) as u8;
    out[19] = (a[7] >> 5) as u8;
    out[20] = (a[7] >> 13) as u8;
    out[21] = a[8] as u8;
    out[22] = (a[8] >> 8) as u8;
    out[23] = ((a[8] >> 16) | (a[9] << 5)) as u8;
    out[24] = (a[9] >> 3) as u8;
    out[25] = (a[9] >> 11) as u8;
    out[26] = ((a[9] >> 19) | (a[10] << 2)) as u8;
    out[27] = (a[10] >> 6) as u8;
    out[28] = ((a[10] >> 14) | (a[11] << 7)) as u8;
    out[29] = (a[11] >> 1) as u8;
    out[30] = (a[11] >> 9) as u8;
    out[31] = (a[11] >> 17) as u8;
    out
}

#[inline]
pub(crate) fn sc_ge(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut borrow: i32 = 0;
    for i in 0..32 {
        let diff = (a[i] as i32) - (b[i] as i32) - borrow;
        borrow = (diff >> 8) & 1;
    }
    borrow == 0
}

pub(crate) fn sc_sub(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut r = [0u8; 32];
    let mut borrow = 0i16;
    for i in 0..32 {
        let d = a[i] as i16 - b[i] as i16 - borrow;
        if d < 0 {
            r[i] = (d + 256) as u8;
            borrow = 1;
        } else {
            r[i] = d as u8;
            borrow = 0;
        }
    }
    r
}

pub(crate) fn sc_addmul_mod_l(r: &[u8; 32], k: &[u8; 32], a: &[u8; 32]) -> [u8; 32] {
    let mut wide = [0u64; 64];
    for i in 0..32 {
        for j in 0..32 {
            wide[i + j] += (k[i] as u64) * (a[j] as u64);
        }
    }

    for i in 0..32 {
        wide[i] += r[i] as u64;
    }

    let mut out64 = [0u8; 64];
    let mut carry = 0u64;
    for i in 0..64 {
        let v = wide[i] + carry;
        out64[i] = (v & 0xFF) as u8;
        carry = v >> 8;
    }
    debug_assert!(carry == 0, "Unexpected carry in sc_addmul_mod_l");

    sc_reduce_mod_l(&mut out64)
}

pub(crate) fn sc_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut wide = [0u64; 64];
    for i in 0..32 {
        for j in 0..32 {
            wide[i + j] += (a[i] as u64) * (b[j] as u64);
        }
    }
    let mut out64 = [0u8; 64];
    let mut carry = 0u64;
    for i in 0..64 {
        let v = wide[i] + carry;
        out64[i] = (v & 0xFF) as u8;
        carry = v >> 8;
    }
    sc_reduce_mod_l(&mut out64)
}
