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

use super::proving_key::ProvingKey;
use crate::zk_engine::groth16::g1::G1Point;
use crate::zk_engine::groth16::g2::G2Point;
use crate::zk_engine::groth16::pairing::Pairing;
use crate::zk_engine::ZKError;

impl ProvingKey {
    pub fn verify_key(&self) -> Result<bool, ZKError> {
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

        let e_alpha_g2 = Pairing::compute(&self.alpha_g1, &G2Point::generator());
        let e_g1_g2 = Pairing::compute(&G1Point::generator(), &G2Point::generator());

        if e_alpha_g2.equals(&e_g1_g2) {
            return Ok(false);
        }

        let e_beta_g1 = Pairing::compute(&self.beta_g1, &G2Point::generator());
        let e_g1_beta = Pairing::compute(&G1Point::generator(), &self.beta_g2);

        if !e_beta_g1.equals(&e_g1_beta) {
            return Ok(false);
        }

        let e_delta_g1 = Pairing::compute(&self.delta_g1, &G2Point::generator());
        let e_g1_delta = Pairing::compute(&G1Point::generator(), &self.delta_g2);

        if !e_delta_g1.equals(&e_g1_delta) {
            return Ok(false);
        }

        Ok(true)
    }
}
