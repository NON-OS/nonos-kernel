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

use alloc::{vec::Vec, collections::BTreeMap, boxed::Box};
use spin::{Mutex, RwLock};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

use super::types::{ZKConfig, ZKStats, ZKProof, ZKError};
use super::groth16::{Groth16Prover, Groth16Verifier, ProvingKey, VerifyingKey, FieldElement};
use super::circuit::{Circuit, CircuitBuilder, Constraint};
use super::setup::TrustedSetup;

pub struct ZKEngine {
    pub(crate) config: ZKConfig,
    circuits: RwLock<BTreeMap<u32, Box<Circuit>>>,
    proving_keys: RwLock<BTreeMap<u32, ProvingKey>>,
    verifying_keys: RwLock<BTreeMap<u32, VerifyingKey>>,
    pub(crate) verification_cache: Mutex<BTreeMap<[u8; 32], bool>>,
    pub(crate) stats: ZKStats,
    next_circuit_id: AtomicU32,
}

impl ZKEngine {
    pub fn new(config: ZKConfig) -> Result<Self, ZKError> {
        let setup = TrustedSetup::load_or_generate(&config)?;

        // Validate setup parameters
        let _ = Groth16Prover::new(&setup)?;
        let _ = Groth16Verifier::new(&setup)?;

        Ok(ZKEngine {
            config: config.clone(),
            circuits: RwLock::new(BTreeMap::new()),
            proving_keys: RwLock::new(BTreeMap::new()),
            verifying_keys: RwLock::new(BTreeMap::new()),
            verification_cache: Mutex::new(BTreeMap::new()),
            stats: ZKStats {
                proofs_generated: AtomicU64::new(0),
                proofs_verified: AtomicU64::new(0),
                verification_failures: AtomicU64::new(0),
                circuits_compiled: AtomicU32::new(0),
                total_proving_time_ms: AtomicU64::new(0),
                total_verification_time_ms: AtomicU64::new(0),
            },
            next_circuit_id: AtomicU32::new(1),
        })
    }

    pub fn compile_circuit(&self, constraints: Vec<Constraint>, num_witnesses: usize) -> Result<u32, ZKError> {
        if constraints.len() > self.config.max_constraints {
            return Err(ZKError::InvalidCircuit);
        }
        if num_witnesses > self.config.max_witnesses {
            return Err(ZKError::InvalidWitness);
        }

        let circuit_id = self.next_circuit_id.fetch_add(1, Ordering::SeqCst);
        let num_constraints = constraints.len();

        let mut builder = CircuitBuilder::new();
        for constraint in constraints {
            builder.add_constraint(constraint)?;
        }

        let circuit = builder.build(num_witnesses)?;

        let start_time = crate::time::timestamp_millis();
        let (proving_key, verifying_key) = Groth16Prover::generate_keys(&circuit)?;
        let key_gen_time = crate::time::timestamp_millis() - start_time;

        {
            let mut circuits = self.circuits.write();
            let mut proving_keys = self.proving_keys.write();
            let mut verifying_keys = self.verifying_keys.write();

            circuits.insert(circuit_id, Box::new(circuit));
            proving_keys.insert(circuit_id, proving_key);
            verifying_keys.insert(circuit_id, verifying_key);
        }

        self.stats.circuits_compiled.fetch_add(1, Ordering::SeqCst);
        crate::log::info!("Compiled circuit {} with {} constraints, key generation took {}ms", circuit_id, num_constraints, key_gen_time);

        Ok(circuit_id)
    }

    pub fn generate_proof(&self, circuit_id: u32, witness: Vec<Vec<u8>>, public_inputs: Vec<Vec<u8>>) -> Result<ZKProof, ZKError> {
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

        let witness_fe: Vec<FieldElement> = witness.iter()
            .map(|bytes| FieldElement::from_bytes(bytes.as_slice()).unwrap_or(FieldElement::zero()))
            .collect();
        let public_inputs_fe: Vec<FieldElement> = public_inputs.iter()
            .map(|bytes| FieldElement::from_bytes(bytes.as_slice()).unwrap_or(FieldElement::zero()))
            .collect();

        let proof_data = Groth16Prover::prove(&proving_key, &circuit, &witness_fe, &public_inputs_fe, circuit_id)?;

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

    pub fn verify_proof(&self, proof: &ZKProof) -> Result<bool, ZKError> {
        let start_time = crate::time::timestamp_millis();

        if self.config.enable_verification_cache {
            let cache = self.verification_cache.lock();
            if let Some(&cached_result) = cache.get(&proof.proof_hash) {
                return Ok(cached_result);
            }
        }

        let verifying_key = {
            let verifying_keys = self.verifying_keys.read();
            verifying_keys.get(&proof.circuit_id).ok_or(ZKError::CircuitNotFound)?.clone()
        };

        let public_inputs_fe: Vec<FieldElement> = proof.public_inputs.iter()
            .map(|bytes| FieldElement::from_bytes(bytes.as_slice()).unwrap_or(FieldElement::zero()))
            .collect();

        let is_valid = Groth16Verifier::verify(&verifying_key, &proof.proof_data, &public_inputs_fe)?;

        if self.config.enable_verification_cache {
            let mut cache = self.verification_cache.lock();
            cache.insert(proof.proof_hash, is_valid);
            if cache.len() > 10000 {
                let oldest_keys: Vec<_> = cache.keys().take(1000).cloned().collect();
                for key in oldest_keys {
                    cache.remove(&key);
                }
            }
        }

        let verification_time = crate::time::timestamp_millis() - start_time;
        self.stats.proofs_verified.fetch_add(1, Ordering::SeqCst);
        self.stats.total_verification_time_ms.fetch_add(verification_time, Ordering::SeqCst);

        if !is_valid {
            self.stats.verification_failures.fetch_add(1, Ordering::SeqCst);
        }

        crate::log::info!("Verified proof for circuit {} in {}ms (result: {})", proof.circuit_id, verification_time, is_valid);
        Ok(is_valid)
    }

    pub fn batch_verify_proofs(&self, proofs: &[ZKProof]) -> Result<Vec<bool>, ZKError> {
        let start_time = crate::time::timestamp_millis();
        let mut results = Vec::with_capacity(proofs.len());

        let mut proofs_by_circuit: BTreeMap<u32, Vec<&ZKProof>> = BTreeMap::new();
        for proof in proofs {
            proofs_by_circuit.entry(proof.circuit_id).or_insert_with(Vec::new).push(proof);
        }

        for (circuit_id, circuit_proofs) in proofs_by_circuit {
            let verifying_key = {
                let verifying_keys = self.verifying_keys.read();
                verifying_keys.get(&circuit_id).ok_or(ZKError::CircuitNotFound)?.clone()
            };

            for proof in circuit_proofs {
                let public_inputs_fe: Vec<FieldElement> = proof.public_inputs.iter()
                    .map(|bytes| FieldElement::from_bytes(bytes.as_slice()).unwrap_or(FieldElement::zero()))
                    .collect();

                let is_valid = Groth16Verifier::verify(&verifying_key, &proof.proof_data, &public_inputs_fe)?;
                results.push(is_valid);

                if !is_valid {
                    self.stats.verification_failures.fetch_add(1, Ordering::SeqCst);
                }
            }
        }

        let batch_time = crate::time::timestamp_millis() - start_time;
        self.stats.proofs_verified.fetch_add(proofs.len() as u64, Ordering::SeqCst);
        self.stats.total_verification_time_ms.fetch_add(batch_time, Ordering::SeqCst);
        crate::log::info!("Batch verified {} proofs in {}ms", proofs.len(), batch_time);

        Ok(results)
    }

    pub fn get_stats(&self) -> &ZKStats {
        &self.stats
    }

    pub fn cleanup(&self) {
        let mut cache = self.verification_cache.lock();
        cache.retain(|_, _| true);
        crate::log::info!("ZK engine cleanup completed");
    }

    pub fn serialize_proof(&self, proof: &ZKProof) -> Vec<u8> {
        let mut serialized = Vec::new();
        serialized.extend_from_slice(&proof.circuit_id.to_le_bytes());
        let proof_bytes = proof.proof_data.serialize();
        serialized.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
        serialized.extend_from_slice(&proof_bytes);
        serialized.extend_from_slice(&(proof.public_inputs.len() as u32).to_le_bytes());
        for input in &proof.public_inputs {
            serialized.extend_from_slice(&(input.len() as u32).to_le_bytes());
            serialized.extend_from_slice(input);
        }
        serialized.extend_from_slice(&proof.proof_hash);
        serialized.extend_from_slice(&proof.created_at.to_le_bytes());
        serialized
    }

    pub fn deserialize_proof(&self, data: &[u8]) -> Result<ZKProof, ZKError> {
        if data.len() < 48 {
            return Err(ZKError::InvalidProof);
        }

        let mut offset = 0;
        let circuit_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        offset += 4;

        let proof_len = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;
        if offset + proof_len > data.len() {
            return Err(ZKError::InvalidProof);
        }
        let proof_data = super::groth16::Proof::deserialize(&data[offset..offset + proof_len])?;
        offset += proof_len;

        if offset + 4 > data.len() {
            return Err(ZKError::InvalidProof);
        }
        let num_inputs = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
        offset += 4;

        let mut public_inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            if offset + 4 > data.len() {
                return Err(ZKError::InvalidProof);
            }
            let input_len = u32::from_le_bytes([data[offset], data[offset + 1], data[offset + 2], data[offset + 3]]) as usize;
            offset += 4;
            if offset + input_len > data.len() {
                return Err(ZKError::InvalidProof);
            }
            public_inputs.push(data[offset..offset + input_len].to_vec());
            offset += input_len;
        }

        if offset + 32 > data.len() {
            return Err(ZKError::InvalidProof);
        }
        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        if offset + 8 > data.len() {
            return Err(ZKError::InvalidProof);
        }
        let created_at = u64::from_le_bytes([
            data[offset], data[offset + 1], data[offset + 2], data[offset + 3],
            data[offset + 4], data[offset + 5], data[offset + 6], data[offset + 7],
        ]);

        Ok(ZKProof { circuit_id, proof_data, public_inputs, proof_hash, created_at })
    }
}
