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

use super::constants::L;

pub(crate) fn sc_is_invalid(s: &[u8; 32]) -> bool {
    let mut borrow: i16 = 0;
    for i in 0..32 {
        let diff = s[i] as i16 - L[i] as i16 - borrow;
        borrow = (diff >> 15) & 1;
    }
    borrow == 0
}

pub(crate) fn sc_reduce(h: &[u8; 64]) -> [u8; 32] {
    let mut acc = [0u8; 64];
    acc.copy_from_slice(h);

    for _ in 0..256 {
        let mut temp = [0u8; 64];
        let mut borrow = 0i16;

        for i in 0..32 {
            let diff = (acc[i] as i16) - (L[i] as i16) - borrow;
            temp[i] = (diff & 0xFF) as u8;
            borrow = (diff >> 8) & 1;
        }
        for i in 32..64 {
            let diff = (acc[i] as i16) - borrow;
            temp[i] = (diff & 0xFF) as u8;
            borrow = (diff >> 8) & 1;
        }

        let mask = ((borrow as u8).wrapping_sub(1)) as u8;
        for i in 0..64 {
            acc[i] = (temp[i] & mask) | (acc[i] & !mask);
        }
    }

    let mut result = [0u8; 32];
    result.copy_from_slice(&acc[..32]);
    result
}

pub(crate) fn sc_mul(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut product = [0u8; 64];

    for i in 0..32 {
        let mut carry = 0u16;
        for j in 0..32 {
            let pos = i + j;
            if pos < 64 {
                let prod = (a[i] as u16) * (b[j] as u16) + (product[pos] as u16) + carry;
                product[pos] = prod as u8;
                carry = prod >> 8;
            }
        }
        if i + 32 < 64 {
            product[i + 32] = product[i + 32].wrapping_add(carry as u8);
        }
    }

    sc_reduce(&product)
}

pub(crate) fn sc_add(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut sum = [0u8; 64];
    let mut carry = 0u16;

    for i in 0..32 {
        let s = (a[i] as u16) + (b[i] as u16) + carry;
        sum[i] = s as u8;
        carry = s >> 8;
    }
    sum[32] = carry as u8;

    sc_reduce(&sum)
}
