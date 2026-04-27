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

use super::result::VerificationResult;
use super::state::Groth16Verifier;
use crate::zk_engine::groth16::{FieldElement, Proof};

impl Groth16Verifier {
    pub fn verify_detailed(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> VerificationResult {
        if let Err(e) = self.validate_inputs(proof, public_inputs) {
            return VerificationResult {
                valid: false,
                error: Some(e),
                timing_ms: 0,
                pairing_checks: 0,
            };
        }

        let start_time = crate::time::timestamp_millis();

        let valid = match self.verify_proof_equation(proof, public_inputs) {
            Ok(result) => result,
            Err(e) => {
                return VerificationResult {
                    valid: false,
                    error: Some(e),
                    timing_ms: crate::time::timestamp_millis() - start_time,
                    pairing_checks: 4,
                };
            }
        };

        VerificationResult {
            valid,
            error: None,
            timing_ms: crate::time::timestamp_millis() - start_time,
            pairing_checks: 4,
        }
    }
}
