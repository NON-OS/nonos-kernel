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

extern crate alloc;
use alloc::vec::Vec;

use super::verifier::Groth16Verifier;
use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::keys::VerifyingKey;
use crate::zk_engine::groth16::proof::Proof;
use crate::zk_engine::ZKError;

pub(super) fn batch_verify_proofs(
    verifying_key: &VerifyingKey,
    proofs: &[Proof],
    public_inputs: &[Vec<FieldElement>],
) -> Result<bool, ZKError> {
    if proofs.len() != public_inputs.len() {
        return Err(ZKError::VerificationFailed);
    }

    for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
        if !Groth16Verifier::verify(verifying_key, proof, inputs)? {
            return Ok(false);
        }
    }

    Ok(true)
}
