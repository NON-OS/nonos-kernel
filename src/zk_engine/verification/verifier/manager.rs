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
use crate::zk_engine::setup::VerifyingKey;
use crate::zk_engine::ZKError;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

pub struct VerificationKeyManager {
    keys: BTreeMap<u32, VerifyingKey>,
}

impl VerificationKeyManager {
    pub fn new() -> Self {
        Self { keys: BTreeMap::new() }
    }

    pub fn add_key(&mut self, circuit_id: u32, key: VerifyingKey) -> Result<(), ZKError> {
        if !key.verify_key()? {
            return Err(ZKError::InvalidCircuit);
        }
        self.keys.insert(circuit_id, key);
        Ok(())
    }

    pub fn get_key(&self, circuit_id: u32) -> Option<&VerifyingKey> {
        self.keys.get(&circuit_id)
    }

    pub fn remove_key(&mut self, circuit_id: u32) -> Option<VerifyingKey> {
        self.keys.remove(&circuit_id)
    }

    pub fn verify_proof(
        &self,
        circuit_id: u32,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<bool, ZKError> {
        let vk = self.get_key(circuit_id).ok_or(ZKError::CircuitNotFound)?;
        let verifier = Groth16Verifier::new(vk.clone());
        verifier.verify(proof, public_inputs)
    }

    pub fn list_circuits(&self) -> Vec<u32> {
        self.keys.keys().copied().collect()
    }

    pub fn key_count(&self) -> usize {
        self.keys.len()
    }
}
