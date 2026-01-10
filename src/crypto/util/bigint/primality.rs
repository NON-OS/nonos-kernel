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

extern crate alloc;

use alloc::vec::Vec;

use super::BigUint;

impl BigUint {
    pub fn is_probably_prime(&self, k: usize) -> bool {
        if self.limbs.len() == 1 {
            let n = self.limbs[0];
            if n < 2 {
                return false;
            }
            if n == 2 || n == 3 {
                return true;
            }
            if n % 2 == 0 {
                return false;
            }
            const SMALL_PRIMES: [u64; 15] = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53];
            for &p in &SMALL_PRIMES {
                if n == p {
                    return true;
                }
                if n % p == 0 {
                    return false;
                }
            }
        }

        if self.is_even() {
            return *self == Self::from_u64(2);
        }

        let n_minus_1 = match self.sub_u64(1) {
            Some(v) => v,
            None => return false,
        };
        let r = n_minus_1.trailing_zeros();
        let d = n_minus_1.shr_bits(r);

        let witnesses: &[u64] = if self.bits() <= 32 {
            &[2, 7, 61]
        } else if self.bits() <= 64 {
            &[2, 325, 9375, 28178, 450775, 9780504, 1795265022]
        } else {
            return self.miller_rabin_random(&d, r, k);
        };

        for &a in witnesses {
            let a_big = Self::from_u64(a);
            if a_big >= *self {
                continue;
            }
            if !self.miller_rabin_witness(&a_big, &d, r) {
                return false;
            }
        }

        true
    }

    fn miller_rabin_witness(&self, a: &Self, d: &Self, r: usize) -> bool {
        let n_minus_1 = match self.sub_u64(1) {
            Some(v) => v,
            None => return false,
        };

        let mut x = match a.mod_pow(d, self) {
            Some(v) => v,
            None => return false,
        };

        if x.is_one() || x == n_minus_1 {
            return true;
        }

        for _ in 0..r - 1 {
            x = x.square() % self;
            if x == n_minus_1 {
                return true;
            }
            if x.is_one() {
                return false;
            }
        }

        false
    }

    fn miller_rabin_random(&self, d: &Self, r: usize, k: usize) -> bool {
        let n_minus_1 = match self.sub_u64(1) {
            Some(v) => v,
            None => return false,
        };
        let two = Self::from_u64(2);

        for _ in 0..k {
            let a = Self::random_range(&two, &n_minus_1);
            if !self.miller_rabin_witness(&a, d, r) {
                return false;
            }
        }

        true
    }

    pub fn random_range(min: &Self, max: &Self) -> Self {
        if min >= max {
            return min.clone();
        }

        let range = max - min;
        let range_bits = range.bits();
        let range_bytes = (range_bits + 7) / 8;

        loop {
            let mut bytes = Vec::with_capacity(range_bytes);
            let mut remaining = range_bytes;

            while remaining > 0 {
                let rng_bytes = crate::crypto::rng::get_random_bytes();
                let take = core::cmp::min(remaining, rng_bytes.len());
                bytes.extend_from_slice(&rng_bytes[..take]);
                remaining = remaining.saturating_sub(take);
            }

            let excess_bits = (range_bytes * 8) - range_bits;
            if excess_bits > 0 && !bytes.is_empty() {
                bytes[0] &= (1u8 << (8 - excess_bits)) - 1;
            }

            let random_val = Self::from_bytes_be(&bytes);

            if random_val < range {
                return min + &random_val;
            }
        }
    }

    pub fn is_prime(&self, k: usize) -> bool {
        self.is_probably_prime(k)
    }
}
