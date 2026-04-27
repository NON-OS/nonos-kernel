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

use crate::zk_engine::groth16::{FieldElement, G1Point, G2Point, VerifyingKey};
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

pub(crate) fn build_verifying_key(
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

    Ok(VerifyingKey { alpha_g1, beta_g2, gamma_g2, delta_g2, ic })
}
