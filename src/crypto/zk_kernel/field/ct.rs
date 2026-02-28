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

use super::types::FieldElement;

impl FieldElement {
    pub fn is_zero(&self) -> bool {
        self.ct_is_zero() == 1
    }

    // SECURITY: Constant-time zero check returns 1 if zero, 0 if non-zero.
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

    // SECURITY: Constant-time equality check returns 1 if equal, 0 if not.
    pub fn ct_eq_u8(&self, other: &Self) -> u8 {
        let mut diff = 0u8;
        for i in 0..32 {
            diff |= self.bytes[i] ^ other.bytes[i];
        }
        let is_nonzero = (diff as u16 | (diff as u16).wrapping_neg()) >> 8;
        (1 ^ is_nonzero) as u8
    }
}
