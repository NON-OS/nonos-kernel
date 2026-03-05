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

//! Setup verification utilities.

use crate::zk_engine::groth16::{G1Point, G2Point, Pairing};
use crate::zk_engine::ZKError;
use super::params::SetupParameters;

/// Setup verification utilities
pub struct SetupVerifier;

impl SetupVerifier {
    pub fn verify_setup(params: &SetupParameters) -> Result<bool, ZKError> {
        // Verify proving key
        if !params.proving_key.verify_key()? {
            return Ok(false);
        }

        // Verify verifying key
        if !params.verifying_key.verify_key()? {
            return Ok(false);
        }

        // Verify consistency between keys (using pairings)
        let pk = &params.proving_key;
        let vk = &params.verifying_key;

        // Check that alpha matches in both keys
        let pairing1 = Pairing::compute(&pk.alpha_g1, &G2Point::generator());
        let pairing2 = Pairing::compute(&vk.alpha_g1, &G2Point::generator());

        if !pairing1.equals(&pairing2) {
            return Ok(false);
        }

        // Check that beta matches in both keys
        let pairing3 = Pairing::compute(&pk.beta_g1, &G2Point::generator());
        let pairing4 = Pairing::compute(&G1Point::generator(), &vk.beta_g2);

        if !pairing3.equals(&pairing4) {
            return Ok(false);
        }

        Ok(true)
    }
}
