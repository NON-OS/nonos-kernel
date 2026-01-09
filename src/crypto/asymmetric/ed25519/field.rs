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

#[derive(Copy, Clone)]
pub(crate) struct Fe(pub(crate) [i32; 10]);

impl Fe {
    #[inline]
    pub(crate) fn zero() -> Self {
        Fe([0; 10])
    }

    #[inline]
    pub(crate) fn one() -> Self {
        let mut t = [0; 10];
        t[0] = 1;
        Fe(t)
    }
}

#[inline]
pub(crate) fn fe_copy(a: &Fe) -> Fe {
    *a
}

#[inline]
pub(crate) fn fe_add(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0i32; 10];
    for i in 0..10 {
        r[i] = a.0[i] + b.0[i];
    }
    Fe(r)
}

#[inline]
pub(crate) fn fe_sub(a: &Fe, b: &Fe) -> Fe {
    let mut r = [0i32; 10];
    for i in 0..10 {
        r[i] = a.0[i] - b.0[i];
    }
    Fe(r)
}

pub(crate) fn fe_mul(a: &Fe, b: &Fe) -> Fe {
    let a0 = a.0[0] as i64;
    let a1 = a.0[1] as i64;
    let a2 = a.0[2] as i64;
    let a3 = a.0[3] as i64;
    let a4 = a.0[4] as i64;
    let a5 = a.0[5] as i64;
    let a6 = a.0[6] as i64;
    let a7 = a.0[7] as i64;
    let a8 = a.0[8] as i64;
    let a9 = a.0[9] as i64;

    let b0 = b.0[0] as i64;
    let b1 = b.0[1] as i64;
    let b2 = b.0[2] as i64;
    let b3 = b.0[3] as i64;
    let b4 = b.0[4] as i64;
    let b5 = b.0[5] as i64;
    let b6 = b.0[6] as i64;
    let b7 = b.0[7] as i64;
    let b8 = b.0[8] as i64;
    let b9 = b.0[9] as i64;

    let b1_19 = b1 * 19;
    let b2_19 = b2 * 19;
    let b3_19 = b3 * 19;
    let b4_19 = b4 * 19;
    let b5_19 = b5 * 19;
    let b6_19 = b6 * 19;
    let b7_19 = b7 * 19;
    let b8_19 = b8 * 19;
    let b9_19 = b9 * 19;
    let a1_2 = a1 * 2;
    let a3_2 = a3 * 2;
    let a5_2 = a5 * 2;
    let a7_2 = a7 * 2;
    let a9_2 = a9 * 2;

    let mut c0 = a0 * b0
        + a1_2 * b9_19
        + a2 * b8_19
        + a3_2 * b7_19
        + a4 * b6_19
        + a5_2 * b5_19
        + a6 * b4_19
        + a7_2 * b3_19
        + a8 * b2_19
        + a9_2 * b1_19;
    let mut c1 = a0 * b1
        + a1 * b0
        + a2 * b9_19
        + a3 * b8_19
        + a4 * b7_19
        + a5 * b6_19
        + a6 * b5_19
        + a7 * b4_19
        + a8 * b3_19
        + a9 * b2_19;
    let mut c2 = a0 * b2
        + a1_2 * b1
        + a2 * b0
        + a3_2 * b9_19
        + a4 * b8_19
        + a5_2 * b7_19
        + a6 * b6_19
        + a7_2 * b5_19
        + a8 * b4_19
        + a9_2 * b3_19;
    let mut c3 = a0 * b3
        + a1 * b2
        + a2 * b1
        + a3 * b0
        + a4 * b9_19
        + a5 * b8_19
        + a6 * b7_19
        + a7 * b6_19
        + a8 * b5_19
        + a9 * b4_19;
    let mut c4 = a0 * b4
        + a1_2 * b3
        + a2 * b2
        + a3_2 * b1
        + a4 * b0
        + a5_2 * b9_19
        + a6 * b8_19
        + a7_2 * b7_19
        + a8 * b6_19
        + a9_2 * b5_19;
    let mut c5 = a0 * b5
        + a1 * b4
        + a2 * b3
        + a3 * b2
        + a4 * b1
        + a5 * b0
        + a6 * b9_19
        + a7 * b8_19
        + a8 * b7_19
        + a9 * b6_19;
    let mut c6 = a0 * b6
        + a1_2 * b5
        + a2 * b4
        + a3_2 * b3
        + a4 * b2
        + a5_2 * b1
        + a6 * b0
        + a7_2 * b9_19
        + a8 * b8_19
        + a9_2 * b7_19;
    let mut c7 = a0 * b7
        + a1 * b6
        + a2 * b5
        + a3 * b4
        + a4 * b3
        + a5 * b2
        + a6 * b1
        + a7 * b0
        + a8 * b9_19
        + a9 * b8_19;
    let mut c8 = a0 * b8
        + a1_2 * b7
        + a2 * b6
        + a3_2 * b5
        + a4 * b4
        + a5_2 * b3
        + a6 * b2
        + a7_2 * b1
        + a8 * b0
        + a9_2 * b9_19;
    let mut c9 = a0 * b9
        + a1 * b8
        + a2 * b7
        + a3 * b6
        + a4 * b5
        + a5 * b4
        + a6 * b3
        + a7 * b2
        + a8 * b1
        + a9 * b0;

    let mut carry: i64;

    carry = (c0 + (1 << 25)) >> 26;
    c1 += carry;
    c0 -= carry << 26;
    carry = (c4 + (1 << 25)) >> 26;
    c5 += carry;
    c4 -= carry << 26;
    carry = (c1 + (1 << 24)) >> 25;
    c2 += carry;
    c1 -= carry << 25;
    carry = (c5 + (1 << 24)) >> 25;
    c6 += carry;
    c5 -= carry << 25;
    carry = (c2 + (1 << 25)) >> 26;
    c3 += carry;
    c2 -= carry << 26;
    carry = (c6 + (1 << 25)) >> 26;
    c7 += carry;
    c6 -= carry << 26;
    carry = (c3 + (1 << 24)) >> 25;
    c4 += carry;
    c3 -= carry << 25;
    carry = (c7 + (1 << 24)) >> 25;
    c8 += carry;
    c7 -= carry << 25;
    carry = (c4 + (1 << 25)) >> 26;
    c5 += carry;
    c4 -= carry << 26;
    carry = (c8 + (1 << 25)) >> 26;
    c9 += carry;
    c8 -= carry << 26;
    carry = (c9 + (1 << 24)) >> 25;
    c0 += carry * 19;
    c9 -= carry << 25;

    carry = (c0 + (1 << 25)) >> 26;
    c1 += carry;
    c0 -= carry << 26;

    Fe([
        c0 as i32, c1 as i32, c2 as i32, c3 as i32, c4 as i32, c5 as i32, c6 as i32, c7 as i32,
        c8 as i32, c9 as i32,
    ])
}

#[inline]
pub(crate) fn fe_sq(a: &Fe) -> Fe {
    fe_mul(a, a)
}

pub(crate) fn fe_invert(z: &Fe) -> Fe {
    let z1 = *z;
    let z2 = fe_sq(&z1);
    let z4 = fe_sq(&z2);
    let z8 = fe_sq(&z4);
    let z9 = fe_mul(&z8, &z1);
    let z11 = fe_mul(&z9, &z2);
    let z22 = fe_sq(&z11);
    let z_5_0 = fe_mul(&z22, &z9);

    let mut t = fe_sq(&z_5_0);
    for _ in 1..5 {
        t = fe_sq(&t);
    }
    let z_10_5 = fe_mul(&t, &z_5_0);

    t = fe_sq(&z_10_5);
    for _ in 1..10 {
        t = fe_sq(&t);
    }
    let z_20_10 = fe_mul(&t, &z_10_5);

    t = fe_sq(&z_20_10);
    for _ in 1..20 {
        t = fe_sq(&t);
    }
    let z_40_20 = fe_mul(&t, &z_20_10);

    t = fe_sq(&z_40_20);
    for _ in 1..10 {
        t = fe_sq(&t);
    }
    let z_50_10 = fe_mul(&t, &z_10_5);

    t = fe_sq(&z_50_10);
    for _ in 1..50 {
        t = fe_sq(&t);
    }
    let z_100_50 = fe_mul(&t, &z_50_10);

    t = fe_sq(&z_100_50);
    for _ in 1..100 {
        t = fe_sq(&t);
    }
    let z_200_100 = fe_mul(&t, &z_100_50);

    t = fe_sq(&z_200_100);
    for _ in 1..50 {
        t = fe_sq(&t);
    }
    let z_250_50 = fe_mul(&t, &z_50_10);

    t = fe_sq(&z_250_50);
    for _ in 1..5 {
        t = fe_sq(&t);
    }
    fe_mul(&t, &z11)
}

pub(crate) fn fe_pow2523(z: &Fe) -> Fe {
    let z1 = *z;
    let z2 = fe_sq(&z1);
    let z4 = fe_sq(&z2);
    let z8 = fe_sq(&z4);
    let z9 = fe_mul(&z8, &z1);
    let z11 = fe_mul(&z9, &z2);
    let z22 = fe_sq(&z11);
    let z_5_0 = fe_mul(&z22, &z9);

    let mut t = fe_sq(&z_5_0);
    for _ in 1..5 {
        t = fe_sq(&t);
    }
    let z_10_5 = fe_mul(&t, &z_5_0);

    t = fe_sq(&z_10_5);
    for _ in 1..10 {
        t = fe_sq(&t);
    }
    let z_20_10 = fe_mul(&t, &z_10_5);

    t = fe_sq(&z_20_10);
    for _ in 1..20 {
        t = fe_sq(&t);
    }
    let z_40_20 = fe_mul(&t, &z_20_10);

    t = fe_sq(&z_40_20);
    for _ in 1..10 {
        t = fe_sq(&t);
    }
    let z_50_10 = fe_mul(&t, &z_10_5);

    t = fe_sq(&z_50_10);
    for _ in 1..50 {
        t = fe_sq(&t);
    }
    let z_100_50 = fe_mul(&t, &z_50_10);

    t = fe_sq(&z_100_50);
    for _ in 1..100 {
        t = fe_sq(&t);
    }
    let z_200_100 = fe_mul(&t, &z_100_50);

    t = fe_sq(&z_200_100);
    for _ in 1..50 {
        t = fe_sq(&t);
    }
    let z_250_50 = fe_mul(&t, &z_50_10);

    t = fe_sq(&z_250_50);
    t = fe_sq(&t);
    fe_mul(&t, &z1)
}

pub(crate) fn fe_tobytes(f: &Fe) -> [u8; 32] {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = f.0[i] as i64;
    }

    let mut carry: i64;
    carry = (h[0] + (1 << 25)) >> 26;
    h[1] += carry;
    h[0] -= carry << 26;
    carry = (h[4] + (1 << 25)) >> 26;
    h[5] += carry;
    h[4] -= carry << 26;
    carry = (h[1] + (1 << 24)) >> 25;
    h[2] += carry;
    h[1] -= carry << 25;
    carry = (h[5] + (1 << 24)) >> 25;
    h[6] += carry;
    h[5] -= carry << 25;
    carry = (h[2] + (1 << 25)) >> 26;
    h[3] += carry;
    h[2] -= carry << 26;
    carry = (h[6] + (1 << 25)) >> 26;
    h[7] += carry;
    h[6] -= carry << 26;
    carry = (h[3] + (1 << 24)) >> 25;
    h[4] += carry;
    h[3] -= carry << 25;
    carry = (h[7] + (1 << 24)) >> 25;
    h[8] += carry;
    h[7] -= carry << 25;
    carry = (h[4] + (1 << 25)) >> 26;
    h[5] += carry;
    h[4] -= carry << 26;
    carry = (h[8] + (1 << 25)) >> 26;
    h[9] += carry;
    h[8] -= carry << 26;
    carry = (h[9] + (1 << 24)) >> 25;
    h[0] += carry * 19;
    h[9] -= carry << 25;

    carry = (h[0] + (1 << 25)) >> 26;
    h[1] += carry;
    h[0] -= carry << 26;

    carry = (h[0] + 19) >> 26;
    carry = (h[1] + carry) >> 25;
    carry = (h[2] + carry) >> 26;
    carry = (h[3] + carry) >> 25;
    carry = (h[4] + carry) >> 26;
    carry = (h[5] + carry) >> 25;
    carry = (h[6] + carry) >> 26;
    carry = (h[7] + carry) >> 25;
    carry = (h[8] + carry) >> 26;
    carry = (h[9] + carry) >> 25;

    h[0] += carry * 19;

    carry = h[0] >> 26;
    h[1] += carry;
    h[0] -= carry << 26;
    carry = h[1] >> 25;
    h[2] += carry;
    h[1] -= carry << 25;
    carry = h[2] >> 26;
    h[3] += carry;
    h[2] -= carry << 26;
    carry = h[3] >> 25;
    h[4] += carry;
    h[3] -= carry << 25;
    carry = h[4] >> 26;
    h[5] += carry;
    h[4] -= carry << 26;
    carry = h[5] >> 25;
    h[6] += carry;
    h[5] -= carry << 25;
    carry = h[6] >> 26;
    h[7] += carry;
    h[6] -= carry << 26;
    carry = h[7] >> 25;
    h[8] += carry;
    h[7] -= carry << 25;
    carry = h[8] >> 26;
    h[9] += carry;
    h[8] -= carry << 26;
    h[9] &= (1 << 25) - 1;

    let mut s = [0u8; 32];
    s[0] = h[0] as u8;
    s[1] = (h[0] >> 8) as u8;
    s[2] = (h[0] >> 16) as u8;
    s[3] = ((h[0] >> 24) | (h[1] << 2)) as u8;
    s[4] = (h[1] >> 6) as u8;
    s[5] = (h[1] >> 14) as u8;
    s[6] = ((h[1] >> 22) | (h[2] << 3)) as u8;
    s[7] = (h[2] >> 5) as u8;
    s[8] = (h[2] >> 13) as u8;
    s[9] = ((h[2] >> 21) | (h[3] << 5)) as u8;
    s[10] = (h[3] >> 3) as u8;
    s[11] = (h[3] >> 11) as u8;
    s[12] = ((h[3] >> 19) | (h[4] << 6)) as u8;
    s[13] = (h[4] >> 2) as u8;
    s[14] = (h[4] >> 10) as u8;
    s[15] = (h[4] >> 18) as u8;
    s[16] = h[5] as u8;
    s[17] = (h[5] >> 8) as u8;
    s[18] = (h[5] >> 16) as u8;
    s[19] = ((h[5] >> 24) | (h[6] << 1)) as u8;
    s[20] = (h[6] >> 7) as u8;
    s[21] = (h[6] >> 15) as u8;
    s[22] = ((h[6] >> 23) | (h[7] << 3)) as u8;
    s[23] = (h[7] >> 5) as u8;
    s[24] = (h[7] >> 13) as u8;
    s[25] = ((h[7] >> 21) | (h[8] << 4)) as u8;
    s[26] = (h[8] >> 4) as u8;
    s[27] = (h[8] >> 12) as u8;
    s[28] = ((h[8] >> 20) | (h[9] << 6)) as u8;
    s[29] = (h[9] >> 2) as u8;
    s[30] = (h[9] >> 10) as u8;
    s[31] = (h[9] >> 18) as u8;
    s
}

pub(crate) fn fe_frombytes(s: &[u8; 32]) -> Fe {
    let h0 = load4(&s[0..4]) as i64;
    let h1 = (load3(&s[4..7]) << 6) as i64;
    let h2 = (load3(&s[7..10]) << 5) as i64;
    let h3 = (load3(&s[10..13]) << 3) as i64;
    let h4 = (load3(&s[13..16]) << 2) as i64;
    let h5 = load4(&s[16..20]) as i64;
    let h6 = (load3(&s[20..23]) << 7) as i64;
    let h7 = (load3(&s[23..26]) << 5) as i64;
    let h8 = (load3(&s[26..29]) << 4) as i64;
    let h9 = ((load3(&s[29..32]) & 0x7fffff) << 2) as i64;

    let mut carry: i64;
    let mut h = [h0, h1, h2, h3, h4, h5, h6, h7, h8, h9];

    carry = (h[9] + (1 << 24)) >> 25;
    h[0] += carry * 19;
    h[9] -= carry << 25;
    carry = (h[1] + (1 << 24)) >> 25;
    h[2] += carry;
    h[1] -= carry << 25;
    carry = (h[3] + (1 << 24)) >> 25;
    h[4] += carry;
    h[3] -= carry << 25;
    carry = (h[5] + (1 << 24)) >> 25;
    h[6] += carry;
    h[5] -= carry << 25;
    carry = (h[7] + (1 << 24)) >> 25;
    h[8] += carry;
    h[7] -= carry << 25;

    carry = (h[0] + (1 << 25)) >> 26;
    h[1] += carry;
    h[0] -= carry << 26;
    carry = (h[2] + (1 << 25)) >> 26;
    h[3] += carry;
    h[2] -= carry << 26;
    carry = (h[4] + (1 << 25)) >> 26;
    h[5] += carry;
    h[4] -= carry << 26;
    carry = (h[6] + (1 << 25)) >> 26;
    h[7] += carry;
    h[6] -= carry << 26;
    carry = (h[8] + (1 << 25)) >> 26;
    h[9] += carry;
    h[8] -= carry << 26;

    Fe([
        h[0] as i32,
        h[1] as i32,
        h[2] as i32,
        h[3] as i32,
        h[4] as i32,
        h[5] as i32,
        h[6] as i32,
        h[7] as i32,
        h[8] as i32,
        h[9] as i32,
    ])
}

#[inline]
pub(crate) fn load3(s: &[u8]) -> i64 {
    (s[0] as i64) | ((s[1] as i64) << 8) | ((s[2] as i64) << 16)
}

#[inline]
pub(crate) fn load4(s: &[u8]) -> i64 {
    (s[0] as i64) | ((s[1] as i64) << 8) | ((s[2] as i64) << 16) | ((s[3] as i64) << 24)
}

#[inline]
pub(crate) fn fe_is_odd(a: &Fe) -> bool {
    fe_tobytes(a)[0] & 1 == 1
}

#[inline]
pub(crate) fn fe_equal(a: &Fe, b: &Fe) -> bool {
    let sa = fe_tobytes(a);
    let sb = fe_tobytes(b);
    ct_eq_32(&sa, &sb)
}

#[inline]
pub(crate) fn ct_eq_32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}

pub(crate) fn fe_cmov(a: &Fe, b: &Fe, mask: u8) -> Fe {
    let mut r = [0i32; 10];
    let m = if mask == 0xFF { !0i32 } else { 0i32 };
    for i in 0..10 {
        r[i] = (a.0[i] & !m) | (b.0[i] & m);
    }
    Fe(r)
}

pub(crate) fn fe_is_zero(f: &Fe) -> bool {
    let mut h = [0i64; 10];
    for i in 0..10 {
        h[i] = f.0[i] as i64;
    }
    let mut carry = [0i64; 10];
    for _ in 0..2 {
        for i in 0..10 {
            carry[i] = (h[i] + (1 << 25)) >> 26;
            h[(i + 1) % 10] += carry[i];
            if i == 9 {
                h[0] += carry[9] * 19;
            }
            h[i] -= carry[i] << 26;
            if i < 9 {
                carry[i + 1] = (h[i + 1] + (1 << 24)) >> 25;
                h[i + 2] += carry[i + 1];
                h[i + 1] -= carry[i + 1] << 25;
            }
        }
    }
    for i in 0..10 {
        if h[i] != 0 {
            return false;
        }
    }
    true
}
