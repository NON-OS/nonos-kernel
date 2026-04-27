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

use super::types::{BigUint, LIMB_BITS};

impl BigUint {
    #[inline]
    pub fn is_zero(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 0
    }
    #[inline]
    pub fn is_one(&self) -> bool {
        self.limbs.len() == 1 && self.limbs[0] == 1
    }
    #[inline]
    pub fn is_odd(&self) -> bool {
        self.limbs[0] & 1 == 1
    }
    #[inline]
    pub fn is_even(&self) -> bool {
        self.limbs[0] & 1 == 0
    }

    pub fn bits(&self) -> usize {
        if self.is_zero() {
            return 0;
        }
        let top_limb = self.limbs[self.limbs.len() - 1];
        let top_bits = LIMB_BITS - top_limb.leading_zeros() as usize;
        (self.limbs.len() - 1) * LIMB_BITS + top_bits
    }

    #[inline]
    pub fn num_limbs(&self) -> usize {
        self.limbs.len()
    }
    #[inline]
    pub fn limbs(&self) -> &[u64] {
        &self.limbs
    }
}
