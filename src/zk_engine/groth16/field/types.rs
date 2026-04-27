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

use super::constants::MONTGOMERY_R;

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct FieldElement {
    pub limbs: [u64; 4],
}

pub type Field = FieldElement;

impl FieldElement {
    pub const ZERO: Self = FieldElement { limbs: [0, 0, 0, 0] };
    pub const ONE: Self = FieldElement { limbs: MONTGOMERY_R };

    pub const fn zero() -> Self {
        Self::ZERO
    }

    pub const fn one() -> Self {
        Self::ONE
    }

    pub const fn from_limbs(limbs: [u64; 4]) -> Self {
        FieldElement { limbs }
    }

    pub fn is_zero(&self) -> bool {
        self.limbs.iter().all(|&x| x == 0)
    }

    pub fn equals(&self, other: &FieldElement) -> bool {
        self == other
    }
}
