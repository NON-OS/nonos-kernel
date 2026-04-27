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

use super::prove_b::compute_b_points;
use super::prove_c::compute_c_point;
use crate::zk_engine::circuit::Circuit;
use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::g1::G1Point;
use crate::zk_engine::groth16::keys::ProvingKey;
use crate::zk_engine::groth16::proof::Proof;
use crate::zk_engine::ZKError;

pub(super) fn create_proof(
    proving_key: &ProvingKey,
    circuit: &Circuit,
    witness: &[FieldElement],
    public_inputs: &[FieldElement],
    circuit_id: u32,
) -> Result<Proof, ZKError> {
    if witness.len() != circuit.num_variables {
        return Err(ZKError::InvalidWitness);
    }

    if public_inputs.len() != circuit.num_inputs {
        return Err(ZKError::InvalidWitness);
    }

    let r = FieldElement::random();
    let s = FieldElement::random();

    let a_point = compute_a_point(proving_key, witness, &r);
    let (b_point_g1, b_point_g2) = compute_b_points(proving_key, witness, &s);
    let c_point = compute_c_point(proving_key, circuit, witness, &a_point, &b_point_g1, &r, &s);

    Ok(Proof { a: a_point, b: b_point_g2, c: c_point, circuit_id })
}

fn compute_a_point(pk: &ProvingKey, witness: &[FieldElement], r: &FieldElement) -> G1Point {
    let mut a_point = pk.alpha_g1.clone();
    for (i, w) in witness.iter().enumerate() {
        if i < pk.a_query.len() {
            let term = pk.a_query[i].scalar_mul(&w.limbs);
            a_point = a_point.add(&term);
        }
    }
    a_point.add(&pk.delta_g1.scalar_mul(&r.limbs))
}
