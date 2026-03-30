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

use super::constants::MONTGOMERY_R2;
use super::types::FieldElement;

impl FieldElement {
    pub fn from_u64(val: u64) -> Self {
        let fe = FieldElement { limbs: [val, 0, 0, 0] };
        fe.to_montgomery()
    }

    pub fn from_u128(val: u128) -> Self {
        let fe = FieldElement { limbs: [val as u64, (val >> 64) as u64, 0, 0] };
        fe.to_montgomery()
    }

    pub fn from_bytes_array(bytes: &[u8; 32]) -> Self {
        Self::from_bytes(bytes).unwrap_or(Self::zero())
    }

    pub fn to_montgomery(self) -> Self {
        self.montgomery_mul(&FieldElement { limbs: MONTGOMERY_R2 })
    }

    pub fn from_montgomery(self) -> Self {
        self.montgomery_mul(&FieldElement::zero())
    }
}
