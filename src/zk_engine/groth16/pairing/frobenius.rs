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

use crate::zk_engine::groth16::g2::{G2Affine, G2FieldElement};

pub(super) fn frobenius_map(p: &G2Affine) -> G2Affine {
    G2Affine {
        x: p.x.conjugate().mul(&G2FieldElement::frobenius_coeff_x_1()),
        y: p.y.conjugate().mul(&G2FieldElement::frobenius_coeff_y_1()),
    }
}

pub(super) fn frobenius_map_neg(p: &G2Affine) -> G2Affine {
    G2Affine {
        x: p.x.conjugate().mul(&G2FieldElement::frobenius_coeff_x_2()),
        y: p.y.conjugate().neg().mul(&G2FieldElement::frobenius_coeff_y_2()),
    }
}
