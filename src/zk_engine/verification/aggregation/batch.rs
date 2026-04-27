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

use super::core::ProofAggregator;
use crate::zk_engine::groth16::{FieldElement, Proof};
use crate::zk_engine::verification::verifier::Groth16Verifier;
use crate::zk_engine::ZKError;
use alloc::vec::Vec;

impl ProofAggregator {
    pub fn batch_verify(
        verifier: &Groth16Verifier,
        proofs: &[Proof],
        all_public_inputs: &[Vec<FieldElement>],
    ) -> Result<bool, ZKError> {
        if proofs.len() != all_public_inputs.len() {
            return Err(ZKError::VerificationFailed);
        }

        if proofs.is_empty() {
            return Ok(true);
        }

        for (proof, inputs) in proofs.iter().zip(all_public_inputs.iter()) {
            if !verifier.verify(proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}
