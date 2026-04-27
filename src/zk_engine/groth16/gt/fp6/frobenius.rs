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
use crate::zk_engine::groth16::g2::G2FieldElement;

impl Fp6Element {
    pub fn frobenius(&self) -> Self {
        Fp6Element {
            c0: self.c0.conjugate(),
            c1: self.c1.conjugate().mul(&G2FieldElement::frobenius_coeff_x_1()),
            c2: self.c2.conjugate().mul(&G2FieldElement::frobenius_coeff_x_2()),
        }
    }

    pub fn frobenius_square(&self) -> Self {
        Fp6Element {
            c0: self.c0,
            c1: self.c1.mul(&G2FieldElement::frobenius_coeff_x_2()),
            c2: self.c2.mul(&G2FieldElement::frobenius_coeff_x_1()),
        }
    }

    pub fn frobenius_cube(&self) -> Self {
        Fp6Element {
            c0: self.c0.conjugate(),
            c1: self.c1.conjugate().neg(),
            c2: self.c2.conjugate(),
        }
    }
}
