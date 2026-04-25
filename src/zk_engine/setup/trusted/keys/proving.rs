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

use crate::zk_engine::groth16::{FieldElement, G1Point, G2Point, ProvingKey};
use crate::zk_engine::setup::powers::Powers;
use crate::zk_engine::ZKError;

pub(crate) fn build_proving_key(
    powers: &Powers,
    a_tau: &[FieldElement],
    b_tau: &[FieldElement],
    c_tau: &[FieldElement],
    alpha: &FieldElement,
    beta: &FieldElement,
    _gamma: &FieldElement,
    delta: &FieldElement,
    num_variables: usize,
    num_inputs: usize,
) -> Result<ProvingKey, ZKError> {
    let g1_gen = G1Point::generator();
    let g2_gen = G2Point::generator();

    let alpha_g1 = g1_gen.scalar_mul(&alpha.limbs);
    let beta_g1 = g1_gen.scalar_mul(&beta.limbs);
    let beta_g2 = g2_gen.scalar_mul(&beta.limbs);
    let delta_g1 = g1_gen.scalar_mul(&delta.limbs);
    let delta_g2 = g2_gen.scalar_mul(&delta.limbs);

    let a_query = super::queries::build_g1_query(&g1_gen, a_tau, num_variables);
    let b_g1_query = super::queries::build_g1_query(&g1_gen, b_tau, num_variables);
    let b_g2_query = super::queries::build_g2_query(&g2_gen, b_tau, num_variables);
    let h_query = powers.tau_g1[..powers.tau_g1.len().saturating_sub(1)].to_vec();
    let l_query = super::queries::build_l_query(
        &g1_gen,
        a_tau,
        b_tau,
        c_tau,
        alpha,
        beta,
        delta,
        num_variables,
        num_inputs,
    )?;

    Ok(ProvingKey {
        alpha_g1,
        beta_g1,
        beta_g2,
        delta_g1,
        delta_g2,
        a_query,
        b_g1_query,
        b_g2_query,
        h_query,
        l_query,
        num_variables,
        num_inputs,
    })
}
