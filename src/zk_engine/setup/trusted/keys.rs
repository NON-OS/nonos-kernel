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

use alloc::vec::Vec;
use crate::zk_engine::groth16::{FieldElement, G1Point, G2Point, ProvingKey, VerifyingKey};
use crate::zk_engine::ZKError;
use crate::zk_engine::setup::powers::Powers;

pub(super) fn build_proving_key(
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

    let mut a_query = Vec::with_capacity(num_variables + 1);
    for i in 0..=num_variables {
        if i < a_tau.len() {
            a_query.push(g1_gen.scalar_mul(&a_tau[i].limbs));
        } else {
            a_query.push(G1Point::identity());
        }
    }

    let mut b_g1_query = Vec::with_capacity(num_variables + 1);
    for i in 0..=num_variables {
        if i < b_tau.len() {
            b_g1_query.push(g1_gen.scalar_mul(&b_tau[i].limbs));
        } else {
            b_g1_query.push(G1Point::identity());
        }
    }

    let mut b_g2_query = Vec::with_capacity(num_variables + 1);
    for i in 0..=num_variables {
        if i < b_tau.len() {
            b_g2_query.push(g2_gen.scalar_mul(&b_tau[i].limbs));
        } else {
            b_g2_query.push(G2Point::identity());
        }
    }

    let h_query = powers.tau_g1[..powers.tau_g1.len().saturating_sub(1)].to_vec();

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

pub(super) fn build_verifying_key(
    a_tau: &[FieldElement],
    alpha: &FieldElement,
    beta: &FieldElement,
    gamma: &FieldElement,
    delta: &FieldElement,
    num_inputs: usize,
) -> Result<VerifyingKey, ZKError> {
    let g1_gen = G1Point::generator();
    let g2_gen = G2Point::generator();

    let alpha_g1 = g1_gen.scalar_mul(&alpha.limbs);
    let beta_g2 = g2_gen.scalar_mul(&beta.limbs);
    let gamma_g2 = g2_gen.scalar_mul(&gamma.limbs);
    let delta_g2 = g2_gen.scalar_mul(&delta.limbs);

    let mut ic = Vec::with_capacity(num_inputs + 1);
    let gamma_inv = gamma.invert().ok_or(ZKError::InvalidProof)?;

    for i in 0..=num_inputs {
        if i < a_tau.len() {
            let ic_i = a_tau[i].mul(&gamma_inv);
            ic.push(g1_gen.scalar_mul(&ic_i.limbs));
        } else {
            ic.push(G1Point::identity());
        }
    }

    Ok(VerifyingKey {
        alpha_g1,
        beta_g2,
        gamma_g2,
        delta_g2,
        ic,
    })
}
