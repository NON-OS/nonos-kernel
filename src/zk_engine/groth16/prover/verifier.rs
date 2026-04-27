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

use crate::zk_engine::groth16::field::FieldElement;
use crate::zk_engine::groth16::keys::VerifyingKey;
use crate::zk_engine::groth16::proof::Proof;
use crate::zk_engine::ZKError;

pub struct Groth16Verifier;

impl Groth16Verifier {
    pub fn new(_setup: &crate::zk_engine::setup::SetupParameters) -> Result<Self, ZKError> {
        Ok(Groth16Verifier)
    }

    pub fn verify(
        verifying_key: &VerifyingKey,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<bool, ZKError> {
        super::verify::verify_proof(verifying_key, proof, public_inputs)
    }

    pub fn batch_verify(
        verifying_key: &VerifyingKey,
        proofs: &[Proof],
        public_inputs: &[Vec<FieldElement>],
    ) -> Result<bool, ZKError> {
        super::batch::batch_verify_proofs(verifying_key, proofs, public_inputs)
    }
}
