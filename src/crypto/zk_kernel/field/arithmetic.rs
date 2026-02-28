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

use super::super::constants::L;
use super::types::FieldElement;

impl FieldElement {
    pub fn add(&self, other: &Self) -> Self {
        let mut result = [0u8; 32];
        let mut carry: u16 = 0;

        for i in 0..32 {
            let sum = self.bytes[i] as u16 + other.bytes[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }

        let mut fe = Self { bytes: result };
        fe.reduce();
        fe
    }

    // SECURITY: Constant-time subtraction with conditional addition of L.
    pub fn sub(&self, other: &Self) -> Self {
        let mut result = [0u8; 32];
        let mut borrow: u16 = 0;

        for i in 0..32 {
            let a = self.bytes[i] as u16;
            let b = other.bytes[i] as u16 + borrow;
            let diff = a.wrapping_sub(b);
            result[i] = diff as u8;
            borrow = (diff >> 8) & 1;
        }

        let mask = 0u8.wrapping_sub(borrow as u8);
        let mut carry: u16 = 0;
        for i in 0..32 {
            let add_l = (L[i] & mask) as u16;
            let sum = result[i] as u16 + add_l + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }

        Self { bytes: result }
    }

    pub fn mul(&self, other: &Self) -> Self {
        let mut product = [0u8; 64];

        for i in 0..32 {
            let mut carry: u16 = 0;
            for j in 0..32 {
                if i + j < 64 {
                    let p = (self.bytes[i] as u16) * (other.bytes[j] as u16)
                          + product[i + j] as u16 + carry;
                    product[i + j] = p as u8;
                    carry = p >> 8;
                }
            }
            if i + 32 < 64 {
                product[i + 32] = product[i + 32].wrapping_add(carry as u8);
            }
        }

        Self::from_bytes_wide(&product)
    }
}
