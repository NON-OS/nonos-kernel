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
use core::ops::Mul;
use super::super::BigUint;

impl Mul<&BigUint> for &BigUint {
    type Output = BigUint;

    fn mul(self, other: &BigUint) -> BigUint {
        if self.is_zero() || other.is_zero() {
            return BigUint::zero();
        }

        let result_len = self.limbs.len() + other.limbs.len();
        let mut result = vec![0u64; result_len];

        for i in 0..self.limbs.len() {
            let mut carry = 0u128;

            for j in 0..other.limbs.len() {
                let product = (self.limbs[i] as u128) * (other.limbs[j] as u128)
                    + (result[i + j] as u128)
                    + carry;
                result[i + j] = product as u64;
                carry = product >> 64;
            }

            let mut k = i + other.limbs.len();
            while carry != 0 {
                let sum = (result[k] as u128) + carry;
                result[k] = sum as u64;
                carry = sum >> 64;
                k += 1;
            }
        }

        BigUint::normalize(result)
    }
}

impl Mul<BigUint> for BigUint {
    type Output = BigUint;
    fn mul(self, other: BigUint) -> BigUint { &self * &other }
}

impl Mul<&BigUint> for BigUint {
    type Output = BigUint;
    fn mul(self, other: &BigUint) -> BigUint { &self * other }
}

impl Mul<BigUint> for &BigUint {
    type Output = BigUint;
    fn mul(self, other: BigUint) -> BigUint { self * &other }
}

impl BigUint {
    pub fn mul_u64(&self, val: u64) -> Self {
        if val == 0 || self.is_zero() {
            return Self::zero();
        }
        if val == 1 {
            return self.clone();
        }

        let mut result = Vec::with_capacity(self.limbs.len() + 1);
        let mut carry = 0u128;

        for &limb in &self.limbs {
            let product = (limb as u128) * (val as u128) + carry;
            result.push(product as u64);
            carry = product >> 64;
        }

        if carry != 0 {
            result.push(carry as u64);
        }

        BigUint { limbs: result }
    }

    pub fn square(&self) -> Self {
        if self.is_zero() {
            return Self::zero();
        }
        if self.is_one() {
            return Self::one();
        }

        self * self
    }
}
