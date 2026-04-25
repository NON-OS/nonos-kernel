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
    pub fn inverse(&self) -> Option<FieldElement> {
        if self.is_zero() {
            return None;
        }
        let mut exp = BN254_MODULUS;
        if exp[0] >= 2 {
            exp[0] -= 2;
        } else {
            Self::sub_assign(&mut exp, &[2, 0, 0, 0]);
        }
        Some(self.pow(&exp))
    }

    pub fn pow(&self, exp: &[u64; 4]) -> FieldElement {
        let mut result = FieldElement::one();
        let mut base = *self;
        for &limb in exp.iter() {
            for bit in 0..64 {
                if (limb >> bit) & 1 == 1 {
                    result = result.mul(&base);
                }
                base = base.mul(&base);
            }
        }
        result
    }

    pub fn invert(&self) -> Option<Self> {
        if self.is_zero() {
            return None;
        }
        let exp = [0x3c208c16d87cfd45, 0x97816a916871ca8d, 0xb85045b68181585d, 0x30644e72e131a029];
        Some(self.pow(&exp))
    }
}
