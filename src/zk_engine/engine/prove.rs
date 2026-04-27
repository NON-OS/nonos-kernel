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

use super::super::groth16::{FieldElement, Groth16Prover};
use super::super::types::{ZKError, ZKProof};
use super::core::ZKEngine;
use alloc::vec::Vec;
use core::sync::atomic::Ordering;

impl ZKEngine {
    pub fn generate_proof(
        &self,
        circuit_id: u32,
        witness: Vec<Vec<u8>>,
        public_inputs: Vec<Vec<u8>>,
    ) -> Result<ZKProof, ZKError> {
        let start_time = crate::time::timestamp_millis();
        let (circuit, proving_key) = {
            let circuits = self.circuits.read();
            let proving_keys = self.proving_keys.read();
            let circuit = circuits.get(&circuit_id).ok_or(ZKError::CircuitNotFound)?.as_ref();
            let proving_key = proving_keys.get(&circuit_id).ok_or(ZKError::CircuitNotFound)?;
            (circuit.clone(), proving_key.clone())
        };
        if witness.len() != circuit.num_variables {
            return Err(ZKError::InvalidWitness);
        }
        let witness_fe: Vec<FieldElement> = witness
            .iter()
            .map(|bytes| FieldElement::from_bytes(bytes.as_slice()).unwrap_or(FieldElement::zero()))
            .collect();
        let public_inputs_fe: Vec<FieldElement> = public_inputs
            .iter()
            .map(|bytes| FieldElement::from_bytes(bytes.as_slice()).unwrap_or(FieldElement::zero()))
            .collect();
        let proof_data = Groth16Prover::prove(
            &proving_key,
            &circuit,
            &witness_fe,
            &public_inputs_fe,
            circuit_id,
        )?;
        let mut hasher_input = Vec::new();
        hasher_input.extend_from_slice(&circuit_id.to_le_bytes());
        hasher_input.extend_from_slice(&proof_data.serialize());
        for input in &public_inputs {
            hasher_input.extend_from_slice(input);
        }
        let proof_hash = crate::crypto::hash::blake3_hash(&hasher_input);
        let mut hash_array = [0u8; 32];
        hash_array.copy_from_slice(&proof_hash[..32]);
        let proof = ZKProof {
            circuit_id,
            proof_data,
            public_inputs,
            proof_hash: hash_array,
            created_at: crate::time::timestamp_millis(),
        };
        let proving_time = crate::time::timestamp_millis() - start_time;
        self.stats.proofs_generated.fetch_add(1, Ordering::SeqCst);
        self.stats.total_proving_time_ms.fetch_add(proving_time, Ordering::SeqCst);
        crate::log::info!("Generated proof for circuit {} in {}ms", circuit_id, proving_time);
        Ok(proof)
    }
}
