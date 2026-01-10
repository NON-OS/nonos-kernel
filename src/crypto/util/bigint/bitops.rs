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

use alloc::vec;
use alloc::vec::Vec;
use core::ops::{BitAnd, BitOr, BitXor, Shl, Shr};

use super::{BigUint, LIMB_BITS};

impl BigUint {
    #[inline]
    pub fn bit(&self, i: usize) -> bool {
        let limb_idx = i / LIMB_BITS;
        let bit_idx = i % LIMB_BITS;

        if limb_idx >= self.limbs.len() {
            false
        } else {
            (self.limbs[limb_idx] >> bit_idx) & 1 == 1
        }
    }

    // SECURITY: Constant-time bit extraction - returns 0 or 1 as u64
    #[inline]
    pub fn bit_ct(&self, i: usize) -> u64 {
        let limb_idx = i / LIMB_BITS;
        let bit_idx = i % LIMB_BITS;

        if limb_idx >= self.limbs.len() {
            0
        } else {
            (self.limbs[limb_idx] >> bit_idx) & 1
        }
    }

    // SECURITY: Constant-time conditional select
    // Returns a if mask is all-1s (0xFFFF...), b if mask is 0
    pub fn ct_select(mask: u64, a: &Self, b: &Self) -> Self {
        let max_len = core::cmp::max(a.limbs.len(), b.limbs.len());
        let mut result = vec![0u64; max_len];

        for i in 0..max_len {
            let a_limb = a.limbs.get(i).copied().unwrap_or(0);
            let b_limb = b.limbs.get(i).copied().unwrap_or(0);
            result[i] = (a_limb & mask) | (b_limb & !mask);
        }

        Self::normalize(result)
    }

    // SECURITY: Constant-time conditional swap
    // Swaps a and b if condition is 1, leaves unchanged if 0
    pub fn ct_swap(condition: u64, a: &mut Self, b: &mut Self) {
        let mask = 0u64.wrapping_sub(condition);
        let max_len = core::cmp::max(a.limbs.len(), b.limbs.len());

        // Extend both to same length
        while a.limbs.len() < max_len {
            a.limbs.push(0);
        }
        while b.limbs.len() < max_len {
            b.limbs.push(0);
        }

        for i in 0..max_len {
            let diff = (a.limbs[i] ^ b.limbs[i]) & mask;
            a.limbs[i] ^= diff;
            b.limbs[i] ^= diff;
        }

        // Normalize after swap
        *a = Self::normalize(core::mem::take(&mut a.limbs));
        *b = Self::normalize(core::mem::take(&mut b.limbs));
    }

    pub fn set_bit(&mut self, i: usize, value: bool) {
        let limb_idx = i / LIMB_BITS;
        let bit_idx = i % LIMB_BITS;

        while limb_idx >= self.limbs.len() {
            self.limbs.push(0);
        }

        if value {
            self.limbs[limb_idx] |= 1u64 << bit_idx;
        } else {
            self.limbs[limb_idx] &= !(1u64 << bit_idx);
            while self.limbs.len() > 1 && self.limbs.last() == Some(&0) {
                self.limbs.pop();
            }
        }
    }

    pub fn trailing_zeros(&self) -> usize {
        if self.is_zero() {
            return 0;
        }

        let mut count = 0;
        for &limb in &self.limbs {
            if limb == 0 {
                count += LIMB_BITS;
            } else {
                count += limb.trailing_zeros() as usize;
                break;
            }
        }
        count
    }

    pub fn leading_zeros(&self) -> usize {
        if self.is_zero() {
            return LIMB_BITS;
        }

        match self.limbs.last() {
            Some(limb) => limb.leading_zeros() as usize,
            None => LIMB_BITS,
        }
    }

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

impl BitAnd<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitand(self, other: &BigUint) -> BigUint {
        let len = core::cmp::min(self.limbs.len(), other.limbs.len());
        let limbs: Vec<u64> = (0..len)
            .map(|i| self.limbs[i] & other.limbs[i])
            .collect();
        BigUint::normalize(limbs)
    }
}

impl BitAnd<BigUint> for BigUint {
    type Output = BigUint;
    fn bitand(self, other: BigUint) -> BigUint { &self & &other }
}

impl BitOr<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitor(self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let limbs: Vec<u64> = (0..max_len)
            .map(|i| {
                let a = self.limbs.get(i).copied().unwrap_or(0);
                let b = other.limbs.get(i).copied().unwrap_or(0);
                a | b
            })
            .collect();
        BigUint { limbs }
    }
}

impl BitOr<BigUint> for BigUint {
    type Output = BigUint;
    fn bitor(self, other: BigUint) -> BigUint { &self | &other }
}

impl BitOr<&BigUint> for BigUint {
    type Output = BigUint;
    fn bitor(self, other: &BigUint) -> BigUint { &self | other }
}

impl BitXor<&BigUint> for &BigUint {
    type Output = BigUint;

    fn bitxor(self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let limbs: Vec<u64> = (0..max_len)
            .map(|i| {
                let a = self.limbs.get(i).copied().unwrap_or(0);
                let b = other.limbs.get(i).copied().unwrap_or(0);
                a ^ b
            })
            .collect();
        BigUint::normalize(limbs)
    }
}

impl BitXor<BigUint> for BigUint {
    type Output = BigUint;
    fn bitxor(self, other: BigUint) -> BigUint { &self ^ &other }
}

impl Shl<usize> for &BigUint {
    type Output = BigUint;
    fn shl(self, n: usize) -> BigUint { self.shl_bits(n) }
}

impl Shl<usize> for BigUint {
    type Output = BigUint;
    fn shl(self, n: usize) -> BigUint { (&self).shl_bits(n) }
}

impl Shr<usize> for &BigUint {
    type Output = BigUint;
    fn shr(self, n: usize) -> BigUint { self.shr_bits(n) }
}

impl Shr<usize> for BigUint {
    type Output = BigUint;
    fn shr(self, n: usize) -> BigUint { (&self).shr_bits(n) }
}
