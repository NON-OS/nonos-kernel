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

use crate::crypto::rng::fill_random_bytes;
use super::constants::L;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FieldElement {
    bytes: [u8; 32],
}

impl FieldElement {
    pub const ZERO: Self = Self { bytes: [0u8; 32] };
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let mut fe = Self { bytes: *bytes };
        fe.reduce();
        fe
    }

    /// Create a field element from 64 bytes using constant-time Barrett reduction.
    ///
    /// # SECURITY: Always performs the same operations regardless of input.
    pub fn from_bytes_wide(bytes: &[u8; 64]) -> Self {
        const MU: [u8; 32] = [
            0x1d, 0x95, 0x98, 0x4d, 0x74, 0x31, 0xec, 0xd6,
            0x70, 0xcf, 0x7d, 0x73, 0xf4, 0x5b, 0xef, 0xc6,
            0xfe, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x0f,
        ];

        let mut acc = [0u32; 64];

        // Copy low bytes
        for i in 0..32 {
            acc[i] += bytes[i] as u32;
        }

        // Reduce high bytes using Barrett constant (constant-time, no early exit)
        for i in 0..32 {
            let hi = bytes[32 + i] as u32;
            for j in 0..32 {
                acc[i + j] += hi * (MU[j] as u32);
            }
        }

        for i in 0..63 {
            acc[i + 1] += acc[i] >> 8;
            acc[i] &= 0xFF;
        }

        let mut result = [0u8; 32];
        for i in 0..32 {
            result[i] = acc[i] as u8;
        }

        // Always process high accumulator (constant-time)
        let mut high_acc = [0u32; 64];
        for i in 32..64 {
            let hi = acc[i] as u32;
            for j in 0..32 {
                high_acc[i - 32 + j] += hi * (MU[j] as u32);
            }
        }

        for i in 0..63 {
            high_acc[i + 1] += high_acc[i] >> 8;
            high_acc[i] &= 0xFF;
        }

        let mut extra = [0u8; 32];
        for i in 0..32 {
            extra[i] = high_acc[i] as u8;
        }

        let mut carry: u16 = 0;
        for i in 0..32 {
            let sum = result[i] as u16 + extra[i] as u16 + carry;
            result[i] = sum as u8;
            carry = sum >> 8;
        }

        let mut fe = Self { bytes: result };
        fe.reduce();
        fe
    }

    pub fn to_bytes(&self) -> [u8; 32] {
        self.bytes
    }

    pub fn random() -> Self {
        let mut bytes = [0u8; 32];
        fill_random_bytes(&mut bytes);
        bytes[31] &= 0x0F;
        Self::from_bytes(&bytes)
    }

    /// # SECURITY: Performs exactly 2 subtractions (sufficient for values < 2L) and uses
    /// constant-time selection based on the borrow flag.
    fn reduce(&mut self) {
        for _ in 0..2 {
            let mut borrow: u8 = 0;
            let mut temp = [0u8; 32];

            for i in 0..32 {
                let a = self.bytes[i] as u16;
                let b = L[i] as u16 + borrow as u16;
                let diff = a.wrapping_sub(b);
                temp[i] = diff as u8;
                borrow = (diff >> 8) as u8 & 1;
            }

            let mask = borrow.wrapping_sub(1);
            for i in 0..32 {
                self.bytes[i] = (temp[i] & mask) | (self.bytes[i] & !mask);
            }
        }
    }

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

    /// # SECURITY: Constant-time subtraction with conditional addition of L.
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

    pub fn is_zero(&self) -> bool {
        self.ct_is_zero() == 1
    }


    pub fn ct_is_zero(&self) -> u8 {
        let mut acc = 0u8;
        for b in &self.bytes {
            acc |= *b;
        }
        let is_nonzero = (acc as u16 | (acc as u16).wrapping_neg()) >> 8;
        (1 ^ is_nonzero) as u8
    }

    pub fn ct_eq(&self, other: &Self) -> bool {
        self.ct_eq_u8(other) == 1
    }

    pub fn ct_eq_u8(&self, other: &Self) -> u8 {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.bytes[i] ^ other.bytes[i];
        }
        let is_nonzero = (diff as u16 | (diff as u16).wrapping_neg()) >> 8;
        (1 ^ is_nonzero) as u8
    }
}
