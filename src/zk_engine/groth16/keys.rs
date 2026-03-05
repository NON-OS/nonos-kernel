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

//! Groth16 proving and verifying key structures.

use alloc::vec::Vec;
use crate::zk_engine::ZKError;
use super::g1::G1Point;
use super::g2::G2Point;
use super::pairing::Pairing;

/// Proving key for Groth16
#[derive(Debug, Clone)]
pub struct ProvingKey {
    pub alpha_g1: G1Point,
    pub beta_g1: G1Point,
    pub beta_g2: G2Point,
    pub delta_g1: G1Point,
    pub delta_g2: G2Point,

    // QAP evaluation at tau
    pub a_query: Vec<G1Point>,     // [A_i(tau)]_1
    pub b_g1_query: Vec<G1Point>,  // [B_i(tau)]_1
    pub b_g2_query: Vec<G2Point>,  // [B_i(tau)]_2
    pub h_query: Vec<G1Point>,     // [tau^i]_1 for i in [0, degree-2]
    pub l_query: Vec<G1Point>,     // [(beta*A_i(tau) + alpha*B_i(tau) + C_i(tau))/delta]_1

    pub num_variables: usize,
    pub num_inputs: usize,
}

impl ProvingKey {
    /// Verify the proving key is well-formed
    pub fn verify_key(&self) -> Result<bool, ZKError> {
        // Basic sanity checks
        if self.a_query.len() != self.num_variables + 1 {
            return Ok(false);
        }

        if self.b_g1_query.len() != self.num_variables + 1 {
            return Ok(false);
        }

        if self.b_g2_query.len() != self.num_variables + 1 {
            return Ok(false);
        }

        if self.l_query.len() != self.num_variables - self.num_inputs {
            return Ok(false);
        }

        // Verify proving key consistency using bilinear pairing properties
        let e_alpha_g2 = Pairing::compute(&self.alpha_g1, &G2Point::generator());
        let e_g1_g2 = Pairing::compute(&G1Point::generator(), &G2Point::generator());

        // Alpha must not be identity
        if e_alpha_g2.equals(&e_g1_g2) {
            return Ok(false);
        }

        // Verify beta consistency
        let e_beta_g1 = Pairing::compute(&self.beta_g1, &G2Point::generator());
        let e_g1_beta = Pairing::compute(&G1Point::generator(), &self.beta_g2);

        if !e_beta_g1.equals(&e_g1_beta) {
            return Ok(false);
        }

        // Verify delta consistency
        let e_delta_g1 = Pairing::compute(&self.delta_g1, &G2Point::generator());
        let e_g1_delta = Pairing::compute(&G1Point::generator(), &self.delta_g2);

        if !e_delta_g1.equals(&e_g1_delta) {
            return Ok(false);
        }

        Ok(true)
    }
}

/// Verifying key for Groth16
#[derive(Debug, Clone)]
pub struct VerifyingKey {
    pub alpha_g1: G1Point,
    pub beta_g2: G2Point,
    pub gamma_g2: G2Point,
    pub delta_g2: G2Point,
    pub ic: Vec<G1Point>, // [IC_0, IC_1, ..., IC_l]_1 where l is number of inputs
}

impl VerifyingKey {
    /// Verify the verifying key is well-formed
    pub fn verify_key(&self) -> Result<bool, ZKError> {
        // Verify that points are not identity
        if self.alpha_g1.is_identity() {
            return Ok(false);
        }

        if self.beta_g2.is_identity() ||
           self.gamma_g2.is_identity() ||
           self.delta_g2.is_identity() {
            return Ok(false);
        }

        // Verify IC has correct length
        if self.ic.is_empty() {
            return Ok(false);
        }

        Ok(true)
    }
}
