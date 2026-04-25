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

use super::constants::BN254_MODULUS;
use super::types::FieldElement;

impl FieldElement {
    pub fn add(&self, other: &FieldElement) -> FieldElement {
        let mut result = [0u64; 4];
        let mut carry = 0u64;
        for i in 0..4 {
            let sum = self.limbs[i] as u128 + other.limbs[i] as u128 + carry as u128;
            result[i] = sum as u64;
            carry = (sum >> 64) as u64;
        }
        if carry != 0 || Self::gte(&result, &BN254_MODULUS) {
            Self::sub_assign(&mut result, &BN254_MODULUS);
        }
        FieldElement { limbs: result }
    }

    pub fn sub(&self, other: &FieldElement) -> FieldElement {
        let mut result = self.limbs;
        if Self::gte(&self.limbs, &other.limbs) {
            Self::sub_assign(&mut result, &other.limbs);
        } else {
            let mut temp = BN254_MODULUS;
            Self::add_assign(&mut temp, &self.limbs);
            Self::sub_assign(&mut temp, &other.limbs);
            result = temp;
        }
        FieldElement { limbs: result }
    }

    pub fn mul(&self, other: &FieldElement) -> FieldElement {
        self.montgomery_mul(other)
    }

    pub fn neg(&self) -> FieldElement {
        if self.is_zero() {
            *self
        } else {
            let mut result = BN254_MODULUS;
            Self::sub_assign(&mut result, &self.limbs);
            FieldElement { limbs: result }
        }
    }

    pub fn square(&self) -> FieldElement {
        self.mul(self)
    }

    pub fn double(&self) -> FieldElement {
        self.add(self)
    }
}
