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

extern crate alloc;

use alloc::vec;
use alloc::vec::Vec;
use super::super::{BigUint, LIMB_BITS};

impl BigUint {
    pub fn shl_bits(&self, n: usize) -> Self {
        if n == 0 || self.is_zero() {
            return self.clone();
        }

        let limb_shift = n / LIMB_BITS;
        let bit_shift = n % LIMB_BITS;

        let new_len = self.limbs.len() + limb_shift + 1;
        let mut result = vec![0u64; new_len];

        if bit_shift == 0 {
            for i in 0..self.limbs.len() {
                result[i + limb_shift] = self.limbs[i];
            }
        } else {
            let mut carry = 0u64;
            for i in 0..self.limbs.len() {
                let limb = self.limbs[i];
                result[i + limb_shift] = (limb << bit_shift) | carry;
                carry = limb >> (LIMB_BITS - bit_shift);
            }
            if carry != 0 {
                result[self.limbs.len() + limb_shift] = carry;
            }
        }

        Self::normalize(result)
    }

    pub fn shr_bits(&self, n: usize) -> Self {
        if n == 0 || self.is_zero() {
            return self.clone();
        }

        let limb_shift = n / LIMB_BITS;
        let bit_shift = n % LIMB_BITS;

        if limb_shift >= self.limbs.len() {
            return Self::zero();
        }

        let new_len = self.limbs.len() - limb_shift;
        let mut result = vec![0u64; new_len];

        if bit_shift == 0 {
            for i in 0..new_len {
                result[i] = self.limbs[i + limb_shift];
            }
        } else {
            for i in 0..new_len {
                let limb = self.limbs[i + limb_shift];
                result[i] = limb >> bit_shift;
                if i + limb_shift + 1 < self.limbs.len() {
                    result[i] |= self.limbs[i + limb_shift + 1] << (LIMB_BITS - bit_shift);
                }
            }
        }

        Self::normalize(result)
    }

    pub fn shl_1(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }

        let mut result = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u64;

        for &limb in &self.limbs {
            let new_carry = limb >> 63;
            result.push((limb << 1) | carry);
            carry = new_carry;
        }

        if carry != 0 {
            result.push(carry);
        }

        Self { limbs: result }
    }

    pub fn shr_1(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }

        let mut result = vec![0u64; self.limbs.len()];
        let mut carry = 0u64;

        for i in (0..self.limbs.len()).rev() {
            let new_carry = (self.limbs[i] & 1) << 63;
            result[i] = (self.limbs[i] >> 1) | carry;
            carry = new_carry;
        }

        Self::normalize(result)
    }

    pub fn shl(&self, n: usize) -> Self { self.shl_bits(n) }
    pub fn shr(&self, n: usize) -> Self { self.shr_bits(n) }
}
