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

use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::gt::fp6::Fp6Element;

#[derive(Debug, Clone, Copy)]
pub struct GTElement {
    pub c0: Fp6Element,
    pub c1: Fp6Element,
}

impl GTElement {
    pub const IDENTITY: Self = GTElement { c0: Fp6Element::ONE, c1: Fp6Element::ZERO };

    pub const ONE: Self = Self::IDENTITY;

    pub fn identity() -> Self {
        Self::IDENTITY
    }

    pub fn one() -> Self {
        Self::ONE
    }

    pub fn from_fp6_pair(c0: Fp6Element, c1: Fp6Element) -> Self {
        GTElement { c0, c1 }
    }

    pub fn is_identity(&self) -> bool {
        self.c0.c0.c0 == FieldElement::ONE
            && self.c0.c0.c1.is_zero()
            && self.c0.c1.is_zero()
            && self.c0.c2.is_zero()
            && self.c1.c0.is_zero()
            && self.c1.c1.is_zero()
            && self.c1.c2.is_zero()
    }

    pub fn equals(&self, other: &GTElement) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}

impl PartialEq for GTElement {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1
    }
}
