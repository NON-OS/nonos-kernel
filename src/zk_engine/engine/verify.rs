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

use super::super::groth16::{FieldElement, Groth16Verifier};
use super::super::types::{ZKError, ZKProof};
use super::super::verification::compute_cache_key;
use super::core::ZKEngine;
use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::Ordering;

impl ZKEngine {
    pub fn verify_proof(&self, proof: &ZKProof) -> Result<bool, ZKError> {
        let start_time = crate::time::timestamp_millis();
        let cache_key =
            compute_cache_key(proof.circuit_id, &proof.proof_hash, &proof.public_inputs);
        if self.config.enable_verification_cache {
            if let Some(cached) = self.verification_cache.get(&cache_key) {
                return Ok(cached);
            }
        }
        let verifying_key = {
            let keys = self.verifying_keys.read();
            keys.get(&proof.circuit_id).ok_or(ZKError::CircuitNotFound)?.clone()
        };
        let inputs: Vec<FieldElement> = proof
            .public_inputs
            .iter()
            .map(|b| FieldElement::from_bytes(b.as_slice()).unwrap_or(FieldElement::zero()))
            .collect();
        let is_valid = Groth16Verifier::verify(&verifying_key, &proof.proof_data, &inputs)?;
        if self.config.enable_verification_cache {
            self.verification_cache.insert(cache_key, is_valid);
            if self.verification_cache.len() > 10000 {
                self.verification_cache.evict_oldest(1000);
            }
        }
        let elapsed = crate::time::timestamp_millis() - start_time;
        self.stats.proofs_verified.fetch_add(1, Ordering::SeqCst);
        self.stats.total_verification_time_ms.fetch_add(elapsed, Ordering::SeqCst);
        if !is_valid {
            self.stats.verification_failures.fetch_add(1, Ordering::SeqCst);
        }
        Ok(is_valid)
    }

    pub fn batch_verify_proofs(&self, proofs: &[ZKProof]) -> Result<Vec<bool>, ZKError> {
        let start_time = crate::time::timestamp_millis();
        let mut results = Vec::with_capacity(proofs.len());
        let mut by_circuit: BTreeMap<u32, Vec<&ZKProof>> = BTreeMap::new();
        for p in proofs {
            by_circuit.entry(p.circuit_id).or_default().push(p);
        }
        for (cid, cproofs) in by_circuit {
            let vk =
                { self.verifying_keys.read().get(&cid).ok_or(ZKError::CircuitNotFound)?.clone() };
            for proof in cproofs {
                let inputs: Vec<FieldElement> = proof
                    .public_inputs
                    .iter()
                    .map(|b| FieldElement::from_bytes(b.as_slice()).unwrap_or(FieldElement::zero()))
                    .collect();
                let valid = Groth16Verifier::verify(&vk, &proof.proof_data, &inputs)?;
                results.push(valid);
                if !valid {
                    self.stats.verification_failures.fetch_add(1, Ordering::SeqCst);
                }
            }
        }
        let elapsed = crate::time::timestamp_millis() - start_time;
        self.stats.proofs_verified.fetch_add(proofs.len() as u64, Ordering::SeqCst);
        self.stats.total_verification_time_ms.fetch_add(elapsed, Ordering::SeqCst);
        Ok(results)
    }
}
