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

use super::types::G1Point;
use alloc::vec::Vec;

impl G1Point {
    pub(super) fn compute_naf(&self, scalar: &[u64; 4]) -> Vec<i8> {
        let mut naf = Vec::new();
        let mut k = *scalar;
        while !Self::is_zero_scalar(&k) {
            if k[0] & 1 == 1 {
                let width = 2;
                let z = (k[0] as i32) & ((1 << (width + 1)) - 1);
                let zi = if z < (1 << width) { z } else { z - (1 << (width + 1)) };
                naf.push(zi as i8);
                if zi < 0 {
                    Self::add_scalar(&mut k, &[(-zi) as u64, 0, 0, 0]);
                } else {
                    Self::sub_scalar(&mut k, &[zi as u64, 0, 0, 0]);
                }
            } else {
                naf.push(0);
            }
            Self::div2_scalar(&mut k);
        }
        naf
    }

    fn is_zero_scalar(k: &[u64; 4]) -> bool {
        k.iter().all(|&x| x == 0)
    }

    fn div2_scalar(k: &mut [u64; 4]) {
        for i in 0..3 {
            k[i] = (k[i] >> 1) | ((k[i + 1] & 1) << 63);
        }
        k[3] >>= 1;
    }

    fn add_scalar(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut carry = 0u64;
        for i in 0..4 {
            let sum = a[i] as u128 + b[i] as u128 + carry as u128;
            a[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
    }

    fn sub_scalar(a: &mut [u64; 4], b: &[u64; 4]) {
        let mut borrow = 0u64;
        for i in 0..4 {
            let (diff, new_borrow) = a[i].overflowing_sub(b[i] + borrow);
            a[i] = diff;
            borrow = new_borrow as u64;
        }
    }
}
