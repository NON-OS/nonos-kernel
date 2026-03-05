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

//! Powers of tau for the setup ceremony.

use alloc::vec::Vec;
use crate::zk_engine::groth16::{FieldElement, G1Point, G2Point, Pairing};
use crate::zk_engine::ZKError;

/// Powers of tau for the setup ceremony
#[derive(Debug, Clone)]
pub struct Powers {
    pub tau_g1: Vec<G1Point>,      // [1, tau, tau^2, ..., tau^n]_1
    pub tau_g2: Vec<G2Point>,      // [1, tau, tau^2, ..., tau^n]_2
    pub alpha_tau_g1: Vec<G1Point>, // [alpha, alpha*tau, alpha*tau^2, ..., alpha*tau^n]_1
    pub beta_tau_g1: Vec<G1Point>,  // [beta, beta*tau, beta*tau^2, ..., beta*tau^n]_1
    pub beta_g2: G2Point,           // [beta]_2
}

impl Powers {
    pub fn new(max_degree: usize) -> Result<Self, ZKError> {
        let tau = FieldElement::random();
        let alpha = FieldElement::random();
        let beta = FieldElement::random();

        let mut tau_g1 = Vec::with_capacity(max_degree + 1);
        let mut tau_g2 = Vec::with_capacity(max_degree + 1);
        let mut alpha_tau_g1 = Vec::with_capacity(max_degree + 1);
        let mut beta_tau_g1 = Vec::with_capacity(max_degree + 1);

        let g1_generator = G1Point::generator();
        let g2_generator = G2Point::generator();

        let mut tau_power = FieldElement::one();

        for _ in 0..=max_degree {
            // tau^i in G1
            tau_g1.push(g1_generator.scalar_mul(&tau_power.limbs));

            // tau^i in G2
            tau_g2.push(g2_generator.scalar_mul(&tau_power.limbs));

            // alpha*tau^i in G1
            let alpha_tau_power = alpha.mul(&tau_power);
            alpha_tau_g1.push(g1_generator.scalar_mul(&alpha_tau_power.limbs));

            // beta*tau^i in G1
            let beta_tau_power = beta.mul(&tau_power);
            beta_tau_g1.push(g1_generator.scalar_mul(&beta_tau_power.limbs));

            // Update tau^i for next iteration
            tau_power = tau_power.mul(&tau);
        }

        // beta in G2
        let beta_g2 = g2_generator.scalar_mul(&beta.limbs);

        Ok(Powers {
            tau_g1,
            tau_g2,
            alpha_tau_g1,
            beta_tau_g1,
            beta_g2,
        })
    }

    pub fn verify_powers(&self) -> Result<bool, ZKError> {
        // Verify consistency of powers using pairings
        // e([1]_1, [tau]_2) = e([tau]_1, [1]_2)
        if self.tau_g1.len() < 2 || self.tau_g2.len() < 2 {
            return Ok(false);
        }

        let pairing1 = Pairing::compute(&self.tau_g1[0], &self.tau_g2[1]);
        let pairing2 = Pairing::compute(&self.tau_g1[1], &self.tau_g2[0]);

        Ok(pairing1.equals(&pairing2))
    }
}
