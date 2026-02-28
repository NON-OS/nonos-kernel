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

use super::serialize::fe_tobytes;
use super::types::Fe;

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
