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

use alloc::{vec::Vec, collections::BTreeMap};
use core::sync::atomic::Ordering;
use super::core::ZKEngine;
use super::super::types::{ZKProof, ZKError};
use super::super::groth16::{Groth16Verifier, FieldElement};

impl ZKEngine {
    pub fn verify_proof(&self, proof: &ZKProof) -> Result<bool, ZKError> {
        let start_time = crate::time::timestamp_millis();
        if self.config.enable_verification_cache { let cache = self.verification_cache.lock(); if let Some(&cached_result) = cache.get(&proof.proof_hash) { return Ok(cached_result); } }
        let verifying_key = { let verifying_keys = self.verifying_keys.read(); verifying_keys.get(&proof.circuit_id).ok_or(ZKError::CircuitNotFound)?.clone() };
        let public_inputs_fe: Vec<FieldElement> = proof.public_inputs.iter().map(|bytes| FieldElement::from_bytes(bytes.as_slice()).unwrap_or(FieldElement::zero())).collect();
        let is_valid = Groth16Verifier::verify(&verifying_key, &proof.proof_data, &public_inputs_fe)?;
        if self.config.enable_verification_cache {
            let mut cache = self.verification_cache.lock();
            cache.insert(proof.proof_hash, is_valid);
            if cache.len() > 10000 { let oldest_keys: Vec<_> = cache.keys().take(1000).cloned().collect(); for key in oldest_keys { cache.remove(&key); } }
        }
        let verification_time = crate::time::timestamp_millis() - start_time;
        self.stats.proofs_verified.fetch_add(1, Ordering::SeqCst);
        self.stats.total_verification_time_ms.fetch_add(verification_time, Ordering::SeqCst);
        if !is_valid { self.stats.verification_failures.fetch_add(1, Ordering::SeqCst); }
        crate::log::info!("Verified proof for circuit {} in {}ms (result: {})", proof.circuit_id, verification_time, is_valid);
        Ok(is_valid)
    }

    pub fn batch_verify_proofs(&self, proofs: &[ZKProof]) -> Result<Vec<bool>, ZKError> {
        let start_time = crate::time::timestamp_millis();
        let mut results = Vec::with_capacity(proofs.len());
        let mut proofs_by_circuit: BTreeMap<u32, Vec<&ZKProof>> = BTreeMap::new();
        for proof in proofs { proofs_by_circuit.entry(proof.circuit_id).or_insert_with(Vec::new).push(proof); }
        for (circuit_id, circuit_proofs) in proofs_by_circuit {
            let verifying_key = { let verifying_keys = self.verifying_keys.read(); verifying_keys.get(&circuit_id).ok_or(ZKError::CircuitNotFound)?.clone() };
            for proof in circuit_proofs {
                let public_inputs_fe: Vec<FieldElement> = proof.public_inputs.iter().map(|bytes| FieldElement::from_bytes(bytes.as_slice()).unwrap_or(FieldElement::zero())).collect();
                let is_valid = Groth16Verifier::verify(&verifying_key, &proof.proof_data, &public_inputs_fe)?;
                results.push(is_valid);
                if !is_valid { self.stats.verification_failures.fetch_add(1, Ordering::SeqCst); }
            }
        }
        let batch_time = crate::time::timestamp_millis() - start_time;
        self.stats.proofs_verified.fetch_add(proofs.len() as u64, Ordering::SeqCst);
        self.stats.total_verification_time_ms.fetch_add(batch_time, Ordering::SeqCst);
        crate::log::info!("Batch verified {} proofs in {}ms", proofs.len(), batch_time);
        Ok(results)
    }
}
