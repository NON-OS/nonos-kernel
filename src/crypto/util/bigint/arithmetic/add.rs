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
use core::ops::Add;
use super::super::BigUint;

impl Add<&BigUint> for &BigUint {
    type Output = BigUint;

    fn add(self, other: &BigUint) -> BigUint {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut result = Vec::with_capacity(max_len + 1);
        let mut carry = 0u64;

        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);

            let sum = (a as u128) + (b as u128) + (carry as u128);
            result.push(sum as u64);
            carry = (sum >> 64) as u64;
        }

        if carry != 0 {
            result.push(carry);
        }

        BigUint { limbs: result }
    }
}

impl Add<BigUint> for BigUint {
    type Output = BigUint;
    fn add(self, other: BigUint) -> BigUint { &self + &other }
}

impl Add<&BigUint> for BigUint {
    type Output = BigUint;
    fn add(self, other: &BigUint) -> BigUint { &self + other }
}

impl Add<BigUint> for &BigUint {
    type Output = BigUint;
    fn add(self, other: BigUint) -> BigUint { self + &other }
}

impl BigUint {
    pub fn add_u64(&self, val: u64) -> Self {
        if val == 0 {
            return self.clone();
        }

        let mut result = self.limbs.clone();
        let mut carry = val as u128;
        let mut i = 0;

        while carry != 0 {
            if i >= result.len() {
                result.push(0);
            }
            let sum = (result[i] as u128) + carry;
            result[i] = sum as u64;
            carry = sum >> 64;
            i += 1;
        }

        BigUint { limbs: result }
    }
}
