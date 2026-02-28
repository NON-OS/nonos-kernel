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

use super::super::BigUint;

impl BigUint {
    pub(crate) fn ct_ge(&self, other: &Self) -> u64 {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut gt: u64 = 0;
        let mut lt: u64 = 0;

        for i in (0..max_len).rev() {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);

            let a_gt_b = Self::ct_gt_limb(a, b);
            let b_gt_a = Self::ct_gt_limb(b, a);

            let undecided = 1 ^ (gt | lt);
            gt |= undecided & a_gt_b;
            lt |= undecided & b_gt_a;
        }

        1 ^ lt
    }

    #[inline]
    pub(crate) fn ct_gt_limb(a: u64, b: u64) -> u64 {
        let diff = b.wrapping_sub(a);
        let b_inv = !b;
        ((b_inv & a) | ((b_inv | a) & diff)) >> 63
    }

    pub(crate) fn ct_is_one(&self) -> u64 {
        if self.limbs.is_empty() {
            return 0;
        }
        let first_is_one = ((self.limbs[0] ^ 1) == 0) as u64;
        let mut rest_zero: u64 = 1;
        for i in 1..self.limbs.len() {
            rest_zero &= (self.limbs[i] == 0) as u64;
        }
        first_is_one & rest_zero
    }

    pub(crate) fn ct_is_zero(&self) -> u64 {
        let mut all_zero: u64 = 1;
        for &limb in &self.limbs {
            all_zero &= (limb == 0) as u64;
        }
        all_zero
    }

    pub(crate) fn ct_is_odd(&self) -> u64 {
        if self.limbs.is_empty() {
            0
        } else {
            self.limbs[0] & 1
        }
    }
}
