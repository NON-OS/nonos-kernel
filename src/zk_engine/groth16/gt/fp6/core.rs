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

use crate::zk_engine::groth16::g2::G2FieldElement;

#[derive(Debug, Clone, Copy)]
pub struct Fp6Element {
    pub c0: G2FieldElement,
    pub c1: G2FieldElement,
    pub c2: G2FieldElement,
}

impl Fp6Element {
    pub const ZERO: Self =
        Fp6Element { c0: G2FieldElement::ZERO, c1: G2FieldElement::ZERO, c2: G2FieldElement::ZERO };

    pub const ONE: Self =
        Fp6Element { c0: G2FieldElement::ONE, c1: G2FieldElement::ZERO, c2: G2FieldElement::ZERO };

    pub fn zero() -> Self {
        Self::ZERO
    }

    pub fn one() -> Self {
        Self::ONE
    }

    pub fn from_fp2(e: G2FieldElement) -> Self {
        Fp6Element { c0: e, c1: G2FieldElement::zero(), c2: G2FieldElement::zero() }
    }
}

impl PartialEq for Fp6Element {
    fn eq(&self, other: &Self) -> bool {
        self.c0 == other.c0 && self.c1 == other.c1 && self.c2 == other.c2
    }
}
