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
use core::cmp::Ordering;
use core::ops::{Add, Mul, Sub};

use super::BigUint;

impl PartialEq for BigUint {
    fn eq(&self, other: &Self) -> bool {
        self.limbs == other.limbs
    }
}

impl PartialOrd for BigUint {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BigUint {
    fn cmp(&self, other: &Self) -> Ordering {
        match self.limbs.len().cmp(&other.limbs.len()) {
            Ordering::Equal => {
                for i in (0..self.limbs.len()).rev() {
                    match self.limbs[i].cmp(&other.limbs[i]) {
                        Ordering::Equal => continue,
                        ord => return ord,
                    }
                }
                Ordering::Equal
            }
            ord => ord,
        }
    }
}

impl BigUint {
    pub fn ct_eq(&self, other: &Self) -> bool {
        let max_len = core::cmp::max(self.limbs.len(), other.limbs.len());
        let mut diff = 0u64;

        for i in 0..max_len {
            let a = self.limbs.get(i).copied().unwrap_or(0);
            let b = other.limbs.get(i).copied().unwrap_or(0);
            diff |= a ^ b;
        }

        diff |= (self.limbs.len() ^ other.limbs.len()) as u64;

        diff == 0
    }
}

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

impl Sub<&BigUint> for &BigUint {
    type Output = BigUint;

    fn sub(self, other: &BigUint) -> BigUint {
        debug_assert!(self >= other, "Subtraction underflow");

        let mut result = self.limbs.clone();
        let mut borrow = 0i128;

        for i in 0..result.len() {
            let a = result[i] as i128;
            let b = other.limbs.get(i).copied().unwrap_or(0) as i128;
            let diff = a - b - borrow;

            if diff < 0 {
                result[i] = (diff + (1i128 << 64)) as u64;
                borrow = 1;
            } else {
                result[i] = diff as u64;
                borrow = 0;
            }
        }

        debug_assert!(borrow == 0, "Subtraction underflow");
        BigUint::normalize(result)
    }
}

impl Sub<BigUint> for BigUint {
    type Output = BigUint;
    fn sub(self, other: BigUint) -> BigUint { &self - &other }
}

impl Sub<&BigUint> for BigUint {
    type Output = BigUint;
    fn sub(self, other: &BigUint) -> BigUint { &self - other }
}

impl Sub<BigUint> for &BigUint {
    type Output = BigUint;
    fn sub(self, other: BigUint) -> BigUint { self - &other }
}

impl BigUint {
    pub fn sub_u64(&self, val: u64) -> Option<Self> {
        if self.limbs.len() == 1 && self.limbs[0] < val {
            return None;
        }

        let mut result = self.limbs.clone();
        let mut borrow = val as u128;
        let mut i = 0;

        while borrow != 0 && i < result.len() {
            if (result[i] as u128) >= borrow {
                result[i] -= borrow as u64;
                borrow = 0;
            } else {
                let diff = ((1u128 << 64) + (result[i] as u128)) - borrow;
                result[i] = diff as u64;
                borrow = 1;
            }
            i += 1;
        }

        if borrow != 0 {
            return None;
        }

        Some(BigUint::normalize(result))
    }

    pub fn saturating_sub(&self, other: &Self) -> Self {
        if self >= other {
            self - other
        } else {
            Self::zero()
        }
    }
}

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
