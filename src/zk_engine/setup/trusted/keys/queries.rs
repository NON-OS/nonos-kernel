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

use crate::zk_engine::groth16::{FieldElement, G1Point, G2Point};
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(super) fn build_g1_query(
    g1_gen: &G1Point,
    tau: &[FieldElement],
    num_variables: usize,
) -> Vec<G1Point> {
    let mut query = Vec::with_capacity(num_variables + 1);
    for i in 0..=num_variables {
        if i < tau.len() {
            query.push(g1_gen.scalar_mul(&tau[i].limbs));
        } else {
            query.push(G1Point::identity());
        }
    }
    query
}

pub(super) fn build_g2_query(
    g2_gen: &G2Point,
    tau: &[FieldElement],
    num_variables: usize,
) -> Vec<G2Point> {
    let mut query = Vec::with_capacity(num_variables + 1);
    for i in 0..=num_variables {
        if i < tau.len() {
            query.push(g2_gen.scalar_mul(&tau[i].limbs));
        } else {
            query.push(G2Point::identity());
        }
    }
    query
}

pub(super) fn build_l_query(
    g1_gen: &G1Point,
    a_tau: &[FieldElement],
    b_tau: &[FieldElement],
    c_tau: &[FieldElement],
    alpha: &FieldElement,
    beta: &FieldElement,
    delta: &FieldElement,
    num_variables: usize,
    num_inputs: usize,
) -> Result<Vec<G1Point>, ZKError> {
    let mut l_query = Vec::new();
    let delta_inv = delta.invert().ok_or(ZKError::InvalidProof)?;

    for i in num_inputs + 1..=num_variables {
        if i < a_tau.len() && i < b_tau.len() && i < c_tau.len() {
            let beta_a = beta.mul(&a_tau[i]);
            let alpha_b = alpha.mul(&b_tau[i]);
            let numerator = beta_a.add(&alpha_b).add(&c_tau[i]);
            let l_i = numerator.mul(&delta_inv);
            l_query.push(g1_gen.scalar_mul(&l_i.limbs));
        }
    }

    Ok(l_query)
}
