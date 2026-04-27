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
use alloc::vec::Vec;

impl Groth16Verifier {
    pub fn batch_verify(
        &self,
        proofs: &[Proof],
        public_inputs: &[Vec<FieldElement>],
    ) -> Result<bool, ZKError> {
        if proofs.len() != public_inputs.len() {
            return Err(ZKError::VerificationFailed);
        }

        if proofs.is_empty() {
            return Ok(true);
        }

        for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
            if !self.verify(proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    pub fn verify_with_timing(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<(bool, u64), ZKError> {
        let start_time = crate::time::timestamp_millis();
        let result = self.verify(proof, public_inputs)?;
        let end_time = crate::time::timestamp_millis();
        Ok((result, end_time - start_time))
    }
}
