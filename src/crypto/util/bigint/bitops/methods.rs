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
use super::super::{BigUint, LIMB_BITS};

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

    pub fn ct_swap(condition: u64, a: &mut Self, b: &mut Self) {
        let mask = 0u64.wrapping_sub(condition);
        let max_len = core::cmp::max(a.limbs.len(), b.limbs.len());

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
}
