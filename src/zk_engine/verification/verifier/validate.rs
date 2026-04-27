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
    pub(super) fn validate_inputs(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<(), ZKError> {
        if proof.a.is_identity() {
            return Err(ZKError::VerificationFailed);
        }
        if proof.b.is_identity() {
            return Err(ZKError::VerificationFailed);
        }
        if proof.c.is_identity() {
            return Err(ZKError::VerificationFailed);
        }
        if public_inputs.len() + 1 != self.verifying_key.ic.len() {
            return Err(ZKError::VerificationFailed);
        }
        if !proof.a.is_on_curve() || !proof.c.is_on_curve() {
            return Err(ZKError::VerificationFailed);
        }
        if !proof.b.is_on_curve() {
            return Err(ZKError::VerificationFailed);
        }
        Ok(())
    }
}
