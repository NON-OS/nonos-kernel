// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::constants::SECP256K1_ORDER;
use crate::crypto::CryptoResult;

pub(super) fn scalar_add(a: &[u8; 32], b: &[u8; 32]) -> CryptoResult<[u8; 32]> {
    let (mut result, mut carry) = ([0u64; 4], 0u64);
    for i in (0..4).rev() {
        let idx = i * 8;
        let a_chunk = u64::from_be_bytes([
            a[idx],
            a[idx + 1],
            a[idx + 2],
            a[idx + 3],
            a[idx + 4],
            a[idx + 5],
            a[idx + 6],
            a[idx + 7],
        ]);
        let b_chunk = u64::from_be_bytes([
            b[idx],
            b[idx + 1],
            b[idx + 2],
            b[idx + 3],
            b[idx + 4],
            b[idx + 5],
            b[idx + 6],
            b[idx + 7],
        ]);
        let (sum1, c1) = a_chunk.overflowing_add(b_chunk);
        let (sum2, c2) = sum1.overflowing_add(carry);
        result[i] = sum2;
        carry = (c1 as u64) + (c2 as u64);
    }
    let order = order_as_u64();
    let mut needs_reduction = carry > 0;
    if !needs_reduction {
        for i in 0..4 {
            if result[i] > order[i] {
                needs_reduction = true;
                break;
            }
            if result[i] < order[i] {
                break;
            }
        }
    }
    if needs_reduction {
        let mut borrow = 0u64;
        for i in (0..4).rev() {
            let (diff, b1) = result[i].overflowing_sub(order[i]);
            let (diff2, b2) = diff.overflowing_sub(borrow);
            result[i] = diff2;
            borrow = (b1 as u64) + (b2 as u64);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..(i + 1) * 8].copy_from_slice(&result[i].to_be_bytes());
    }
    Ok(out)
}

fn order_as_u64() -> [u64; 4] {
    [
        u64::from_be_bytes([
            SECP256K1_ORDER[0],
            SECP256K1_ORDER[1],
            SECP256K1_ORDER[2],
            SECP256K1_ORDER[3],
            SECP256K1_ORDER[4],
            SECP256K1_ORDER[5],
            SECP256K1_ORDER[6],
            SECP256K1_ORDER[7],
        ]),
        u64::from_be_bytes([
            SECP256K1_ORDER[8],
            SECP256K1_ORDER[9],
            SECP256K1_ORDER[10],
            SECP256K1_ORDER[11],
            SECP256K1_ORDER[12],
            SECP256K1_ORDER[13],
            SECP256K1_ORDER[14],
            SECP256K1_ORDER[15],
        ]),
        u64::from_be_bytes([
            SECP256K1_ORDER[16],
            SECP256K1_ORDER[17],
            SECP256K1_ORDER[18],
            SECP256K1_ORDER[19],
            SECP256K1_ORDER[20],
            SECP256K1_ORDER[21],
            SECP256K1_ORDER[22],
            SECP256K1_ORDER[23],
        ]),
        u64::from_be_bytes([
            SECP256K1_ORDER[24],
            SECP256K1_ORDER[25],
            SECP256K1_ORDER[26],
            SECP256K1_ORDER[27],
            SECP256K1_ORDER[28],
            SECP256K1_ORDER[29],
            SECP256K1_ORDER[30],
            SECP256K1_ORDER[31],
        ]),
    ]
}

pub(super) fn normalize_scalar(mut s: [u8; 32]) -> [u8; 32] {
    if cmp_be_32(&s, &SECP256K1_ORDER) >= 0 {
        s = sub_be_32(&s, &SECP256K1_ORDER);
    }
    if s.iter().all(|&b| b == 0) {
        s[31] = 1;
    }
    s
}

fn cmp_be_32(a: &[u8; 32], b: &[u8; 32]) -> i8 {
    for i in 0..32 {
        if a[i] > b[i] {
            return 1;
        }
        if a[i] < b[i] {
            return -1;
        }
    }
    0
}

fn sub_be_32(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let (mut out, mut borrow) = ([0u8; 32], 0i16);
    for i in (0..32).rev() {
        let mut d = a[i] as i16 - b[i] as i16 - borrow;
        if d < 0 {
            d += 256;
            borrow = 1;
        } else {
            borrow = 0;
        }
        out[i] = d as u8;
    }
    out
}
