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

use super::types::Scalar;

pub(crate) fn reduce(s: &mut Scalar) {
    let mut borrow = 0i128;
    let mut temp = [0u64; 4];

    for i in 0..4 {
        borrow += s.0[i] as i128 - Scalar::N[i] as i128;
        if borrow < 0 {
            temp[i] = (borrow + (1i128 << 64)) as u64;
            borrow = -1;
        } else {
            temp[i] = borrow as u64;
            borrow = 0;
        }
    }

    let no_borrow = ((borrow >> 127) & 1) as u64;
    let mask = no_borrow.wrapping_sub(1);
    for i in 0..4 {
        s.0[i] = (temp[i] & mask) | (s.0[i] & !mask);
    }
}

fn reduce_wide(wide: &[u128; 8]) -> Scalar {
    let mut w = [0u64; 8];
    for i in 0..8 {
        w[i] = wide[i] as u64;
    }

    const R: [u64; 4] = [
        0x402DA1732FC9BEBF,
        0x4551231950B75FC4,
        0x0000000000000001,
        0x0000000000000000,
    ];

    let mut acc = [0u128; 8];

    for i in 0..4 {
        acc[i] = w[i] as u128;
    }

    for i in 0..4 {
        for j in 0..4 {
            acc[i + j] += (w[4 + i] as u128) * (R[j] as u128);
        }
    }

    for i in 0..7 {
        acc[i + 1] += acc[i] >> 64;
        acc[i] &= 0xFFFFFFFFFFFFFFFF;
    }

    let mut result = [0u64; 4];
    for i in 0..4 {
        result[i] = acc[i] as u64;
    }

    let mut overflow = [0u64; 4];
    for i in 0..4 {
        overflow[i] = acc[4 + i] as u64;
    }

    let mut has_overflow = 0u64;
    for i in 0..4 {
        has_overflow |= overflow[i];
    }

    if has_overflow != 0 {
        let mut carry = 0u128;
        for i in 0..4 {
            for j in 0..4 {
                if i + j < 4 {
                    carry += (overflow[i] as u128) * (R[j] as u128);
                    carry += result[i + j] as u128;
                    result[i + j] = carry as u64;
                    carry >>= 64;
                }
            }
        }
    }

    let mut res = Scalar(result);
    reduce(&mut res);
    reduce(&mut res);
    res
}

impl Scalar {
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u64; 4];
        let mut carry = 0u128;

        for i in 0..4 {
            carry += self.0[i] as u128 + other.0[i] as u128;
            result[i] = carry as u64;
            carry >>= 64;
        }

        let mut res = Self(result);
        reduce(&mut res);
        res
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut t = [0u128; 8];

        for i in 0..4 {
            for j in 0..4 {
                t[i + j] += self.0[i] as u128 * other.0[j] as u128;
            }
        }

        for i in 0..7 {
            t[i + 1] += t[i] >> 64;
            t[i] &= 0xFFFFFFFFFFFFFFFF;
        }

        reduce_wide(&t)
    }
}
