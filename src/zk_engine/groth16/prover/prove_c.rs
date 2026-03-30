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

use crate::zk_engine::circuit::Circuit;
use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::g1::G1Point;
use crate::zk_engine::groth16::keys::ProvingKey;

pub(super) fn compute_c_point(
    pk: &ProvingKey,
    circuit: &Circuit,
    witness: &[FieldElement],
    a_point: &G1Point,
    b_point_g1: &G1Point,
    r: &FieldElement,
    s: &FieldElement,
) -> G1Point {
    let mut c_point = G1Point::identity();

    for (i, w) in witness.iter().enumerate().skip(circuit.num_inputs + 1) {
        let idx = i - circuit.num_inputs - 1;
        if idx < pk.l_query.len() {
            let term = pk.l_query[idx].scalar_mul(&w.limbs);
            c_point = c_point.add(&term);
        }
    }

    c_point = c_point.add(&a_point.scalar_mul(&s.limbs));
    c_point = c_point.add(&b_point_g1.scalar_mul(&r.limbs));

    let rs = r.mul(s);
    c_point.add(&pk.delta_g1.scalar_mul(&rs.limbs).neg())
}
