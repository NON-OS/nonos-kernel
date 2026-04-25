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

use super::core::Fp6Element;
use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::g2::G2FieldElement;

impl Fp6Element {
    pub fn mul_by_fp2(&self, e: &G2FieldElement) -> Self {
        Fp6Element { c0: self.c0.mul(e), c1: self.c1.mul(e), c2: self.c2.mul(e) }
    }

    pub fn mul_by_nonresidue(&self) -> Self {
        Fp6Element { c0: Self::mul_by_nonresidue_fp2(&self.c2), c1: self.c0, c2: self.c1 }
    }

    pub fn mul_by_nonresidue_fp2(e: &G2FieldElement) -> G2FieldElement {
        let nine = FieldElement::from_u64(9);
        G2FieldElement { c0: nine.mul(&e.c0).sub(&e.c1), c1: nine.mul(&e.c1).add(&e.c0) }
    }
}
