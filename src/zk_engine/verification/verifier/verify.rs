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
use crate::zk_engine::groth16::{FieldElement, Proof};
use crate::zk_engine::ZKError;

impl Groth16Verifier {
    pub fn verify(&self, proof: &Proof, public_inputs: &[FieldElement]) -> Result<bool, ZKError> {
        self.validate_inputs(proof, public_inputs)?;
        self.verify_proof_equation(proof, public_inputs)
    }

    pub fn verify_no_inputs(&self, proof: &Proof) -> Result<bool, ZKError> {
        self.verify(proof, &[])
    }

    pub fn verify_for_circuit(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
        expected_circuit_id: u32,
    ) -> Result<bool, ZKError> {
        if proof.circuit_id != expected_circuit_id {
            return Err(ZKError::CircuitNotFound);
        }
        self.verify(proof, public_inputs)
    }

    pub fn preprocess_vk(&mut self) -> Result<(), ZKError> {
        self.verifying_key.verify_key()?;
        Ok(())
    }
}
