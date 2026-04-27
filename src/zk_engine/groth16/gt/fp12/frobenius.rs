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

use super::core::GTElement;
use crate::zk_engine::groth16::g2::G2FieldElement;

impl GTElement {
    pub fn frobenius(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius(),
            c1: self.c1.frobenius().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12()),
        }
    }

    pub fn frobenius_square(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius_square(),
            c1: self.c1.frobenius_square().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12_sq()),
        }
    }

    pub fn frobenius_cube(&self) -> GTElement {
        GTElement {
            c0: self.c0.frobenius_cube(),
            c1: self.c1.frobenius_cube().mul_by_fp2(&G2FieldElement::frobenius_coeff_fp12_cub()),
        }
    }
}
