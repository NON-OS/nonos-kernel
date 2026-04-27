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

use super::constants::{BN254_MODULUS, MONTGOMERY_INV};
use super::types::FieldElement;

impl FieldElement {
    pub fn montgomery_mul(&self, other: &FieldElement) -> FieldElement {
        let mut t = [0u64; 8];
        for i in 0..4 {
            let mut c = 0u128;
            for j in 0..4 {
                let prod =
                    (self.limbs[i] as u128) * (other.limbs[j] as u128) + (t[i + j] as u128) + c;
                t[i + j] = prod as u64;
                c = prod >> 64;
            }
            t[i + 4] = c as u64;
        }
        for i in 0..4 {
            let k = (t[i] as u128 * MONTGOMERY_INV as u128) as u64;
            let mut c = 0u128;
            for j in 0..4 {
                let prod = (k as u128) * (BN254_MODULUS[j] as u128) + (t[i + j] as u128) + c;
                if i + j == 0 {
                    c = prod >> 64;
                } else {
                    t[i + j] = prod as u64;
                    c = prod >> 64;
                }
            }
            for j in 4..8 - i {
                let sum = (t[i + j] as u128) + c;
                t[i + j] = sum as u64;
                c = sum >> 64;
            }
        }
        let mut result = [t[4], t[5], t[6], t[7]];
        if Self::gte(&result, &BN254_MODULUS) {
            Self::sub_assign(&mut result, &BN254_MODULUS);
        }
        FieldElement { limbs: result }
    }
}
