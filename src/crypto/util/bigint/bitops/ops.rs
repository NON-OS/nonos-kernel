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

use alloc::vec::Vec;
use core::ops::{BitAnd, BitOr, BitXor, Shl, Shr};
use super::super::BigUint;

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
