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

use super::state::Groth16Verifier;
use crate::zk_engine::groth16::{FieldElement, G1Point, Pairing, Proof};
use crate::zk_engine::ZKError;

impl Groth16Verifier {
    pub(super) fn verify_proof_equation(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<bool, ZKError> {
        let vk_x = self.compute_vk_x(public_inputs)?;

        let pairing1 = Pairing::compute(&proof.a, &proof.b);
        let pairing2 =
            Pairing::compute(&self.verifying_key.alpha_g1.negate(), &self.verifying_key.beta_g2);
        let pairing3 = Pairing::compute(&vk_x.negate(), &self.verifying_key.gamma_g2);
        let pairing4 = Pairing::compute(&proof.c.negate(), &self.verifying_key.delta_g2);

        let result = pairing1.multiply(&pairing2).multiply(&pairing3).multiply(&pairing4);
        Ok(result.is_identity())
    }

    pub fn compute_vk_x(&self, public_inputs: &[FieldElement]) -> Result<G1Point, ZKError> {
        if self.verifying_key.ic.is_empty() {
            return Err(ZKError::VerificationFailed);
        }

        let mut vk_x = self.verifying_key.ic[0];

        for (i, input) in public_inputs.iter().enumerate() {
            if i + 1 >= self.verifying_key.ic.len() {
                return Err(ZKError::VerificationFailed);
            }
            let term = self.verifying_key.ic[i + 1].scalar_mul(&input.limbs);
            vk_x = vk_x.add(&term);
        }

        Ok(vk_x)
    }
}
