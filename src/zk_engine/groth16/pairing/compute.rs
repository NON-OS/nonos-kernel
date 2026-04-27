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

use super::final_exp::final_exponentiation;
use super::miller::miller_loop;
use crate::zk_engine::groth16::g1::G1Point;
use crate::zk_engine::groth16::g2::G2Point;
use crate::zk_engine::groth16::gt::GTElement;

pub struct Pairing;

impl Pairing {
    pub fn compute(p: &G1Point, q: &G2Point) -> GTElement {
        if p.is_infinity() || q.is_infinity() {
            return GTElement::identity();
        }

        let p_affine = p.to_affine();
        let q_affine = q.to_affine();

        let f = miller_loop(&p_affine, &q_affine);

        final_exponentiation(&f)
    }

    pub fn multi_pairing(pairs: &[(G1Point, G2Point)]) -> GTElement {
        let mut product = GTElement::one();

        for (p, q) in pairs {
            let pairing = Self::compute(p, q);
            product = product.mul(&pairing);
        }

        product
    }
}
