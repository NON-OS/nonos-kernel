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
use crate::zk_engine::groth16::g1::G1Point;
use crate::zk_engine::groth16::g2::G2Point;
use crate::zk_engine::groth16::keys::ProvingKey;

pub(super) fn compute_b_points(
    pk: &ProvingKey,
    witness: &[FieldElement],
    s: &FieldElement,
) -> (G1Point, G2Point) {
    let mut b_point_g1 = pk.beta_g1.clone();
    let mut b_point_g2 = pk.beta_g2.clone();
    for (i, w) in witness.iter().enumerate() {
        if i < pk.b_g1_query.len() {
            let term_g1 = pk.b_g1_query[i].scalar_mul(&w.limbs);
            let term_g2 = pk.b_g2_query[i].scalar_mul(&w.limbs);
            b_point_g1 = b_point_g1.add(&term_g1);
            b_point_g2 = b_point_g2.add(&term_g2);
        }
    }
    b_point_g2 = b_point_g2.add(&pk.delta_g2.scalar_mul(&s.limbs));
    (b_point_g1, b_point_g2)
}
