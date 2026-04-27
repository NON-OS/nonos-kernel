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

use super::types::Powers;
use crate::zk_engine::groth16::{FieldElement, G1Point, G2Point};
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl Powers {
    pub fn new(max_degree: usize) -> Result<Self, ZKError> {
        let tau = FieldElement::random();
        let alpha = FieldElement::random();
        let beta = FieldElement::random();

        let mut tau_g1 = Vec::with_capacity(max_degree + 1);
        let mut tau_g2 = Vec::with_capacity(max_degree + 1);
        let mut alpha_tau_g1 = Vec::with_capacity(max_degree + 1);
        let mut beta_tau_g1 = Vec::with_capacity(max_degree + 1);

        let g1_gen = G1Point::generator();
        let g2_gen = G2Point::generator();

        let mut tau_power = FieldElement::one();

        for _ in 0..=max_degree {
            tau_g1.push(g1_gen.scalar_mul(&tau_power.limbs));
            tau_g2.push(g2_gen.scalar_mul(&tau_power.limbs));

            let alpha_tau_power = alpha.mul(&tau_power);
            alpha_tau_g1.push(g1_gen.scalar_mul(&alpha_tau_power.limbs));

            let beta_tau_power = beta.mul(&tau_power);
            beta_tau_g1.push(g1_gen.scalar_mul(&beta_tau_power.limbs));

            tau_power = tau_power.mul(&tau);
        }

        let beta_g2 = g2_gen.scalar_mul(&beta.limbs);

        Ok(Powers { tau_g1, tau_g2, alpha_tau_g1, beta_tau_g1, beta_g2 })
    }
}
