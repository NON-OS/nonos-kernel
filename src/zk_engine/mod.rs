//! Zero-Knowledge Engine for NONOS Kernel
//!
//! Production ZK-Engine with syscalls sys_zk_prove and sys_zk_verify:
//! - Groth16 proving system
//! - Kernel-level zk-SNARK verification
//! - Circuit compilation and proving
//! - Trusted setup management
//! - Performance optimization for kernel context

use alloc::{boxed::Box, collections::BTreeMap, string::String, vec::Vec};
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use spin::{Mutex, RwLock};

pub mod attestation;
pub mod circuit;
pub mod groth16;
pub mod setup;
pub mod syscalls;
pub mod verification;

use attestation::{init_attestation_manager, AttestationManager};
use circuit::{Circuit, CircuitBuilder, Constraint};
use groth16::{Groth16Prover, Groth16Verifier, Proof, ProvingKey, VerifyingKey};
use setup::{SetupParameters, TrustedSetup};
use verification::{Groth16Verifier as StandaloneVerifier, VerificationKeyManager};

/// Global ZK engine instance
static ZK_ENGINE: spin::Once<ZKEngine> = spin::Once::new();

/// ZK Engine configuration
#[derive(Debug, Clone)]
pub struct ZKConfig {
    pub max_constraints: usize,
    pub max_witnesses: usize,
    pub enable_preprocessing: bool,
    pub enable_verification_cache: bool,
    pub trusted_setup_path: Option<String>,
}

impl Default for ZKConfig {
    fn default() -> Self {
        Self {
            max_constraints: 1_000_000,
            max_witnesses: 100_000,
            enable_preprocessing: true,
            enable_verification_cache: true,
            trusted_setup_path: None,
        }
    }
}

/// Main Zero-Knowledge Engine
pub struct ZKEngine {
    config: ZKConfig,
    prover: Groth16Prover,
    verifier: Groth16Verifier,
    circuits: RwLock<BTreeMap<u32, Box<Circuit>>>,
    proving_keys: RwLock<BTreeMap<u32, ProvingKey>>,
    verifying_keys: RwLock<BTreeMap<u32, VerifyingKey>>,
    verification_cache: Mutex<BTreeMap<[u8; 32], bool>>, // proof_hash -> valid
    stats: ZKStats,
    next_circuit_id: AtomicU32,
}

/// ZK Engine Statistics
#[derive(Debug)]
pub struct ZKStats {
    pub proofs_generated: AtomicU64,
    pub proofs_verified: AtomicU64,
    pub verification_failures: AtomicU64,
    pub circuits_compiled: AtomicU32,
    pub total_proving_time_ms: AtomicU64,
    pub total_verification_time_ms: AtomicU64,
}

/// Proof data structure
#[derive(Debug, Clone)]
pub struct ZKProof {
    pub circuit_id: u32,
    pub proof_data: groth16::Proof,
    pub public_inputs: Vec<Vec<u8>>,
    pub proof_hash: [u8; 32],
    pub created_at: u64,
}

/// Error types for ZK operations
#[derive(Debug, Clone)]
pub enum ZKError {
    InvalidCircuit,
    InvalidWitness,
    ProvingFailed,
    VerificationFailed,
    CircuitNotFound,
    InvalidProof,
    SetupError,
    OutOfMemory,
    InvalidParameters,
    TrustedSetupNotFound,
    InvalidFormat,
    CryptoError,
    InvalidInput,
    NetworkError,
    AttestationError(String),
    NotInitialized,
}

impl ZKEngine {
    /// Create new ZK engine with configuration
    pub fn new(config: ZKConfig) -> Result<Self, ZKError> {
        // Initialize trusted setup
        let setup = TrustedSetup::load_or_generate(&config)?;

        Ok(ZKEngine {
            config: config.clone(),
            prover: Groth16Prover::new(&setup)?,
            verifier: Groth16Verifier::new(&setup)?,
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

    /// Compile circuit from constraints
    pub fn compile_circuit(
        &self,
        constraints: Vec<Constraint>,
        num_witnesses: usize,
    ) -> Result<u32, ZKError> {
        if constraints.len() > self.config.max_constraints {
            return Err(ZKError::InvalidCircuit);
        }

        if num_witnesses > self.config.max_witnesses {
            return Err(ZKError::InvalidWitness);
        }

        let circuit_id = self.next_circuit_id.fetch_add(1, Ordering::SeqCst);
        let num_constraints = constraints.len();

        // Build circuit
        let mut builder = CircuitBuilder::new();
        for constraint in constraints {
            builder.add_constraint(constraint)?;
        }

        let circuit = builder.build(num_witnesses)?;

        // Generate proving and verifying keys
        let start_time = crate::time::timestamp_millis();
        let (proving_key, verifying_key) = Groth16Prover::generate_keys(&circuit)?;
        let key_gen_time = crate::time::timestamp_millis() - start_time;

        // Store circuit and keys
        {
            let mut circuits = self.circuits.write();
            let mut proving_keys = self.proving_keys.write();
            let mut verifying_keys = self.verifying_keys.write();

            circuits.insert(circuit_id, Box::new(circuit));
            proving_keys.insert(circuit_id, proving_key);
            verifying_keys.insert(circuit_id, verifying_key);
        }

        self.stats.circuits_compiled.fetch_add(1, Ordering::SeqCst);

        crate::log::info!(
            "Compiled circuit {} with {} constraints, key generation took {}ms",
            circuit_id,
            num_constraints,
            key_gen_time
        );

        Ok(circuit_id)
    }

    /// Generate proof for circuit with witness
    pub fn generate_proof(
        &self,
        circuit_id: u32,
        witness: Vec<Vec<u8>>,
        public_inputs: Vec<Vec<u8>>,
    ) -> Result<ZKProof, ZKError> {
        let start_time = crate::time::timestamp_millis();

        // Get circuit and proving key
        let (circuit, proving_key) = {
            let circuits = self.circuits.read();
            let proving_keys = self.proving_keys.read();

            let circuit = circuits.get(&circuit_id).ok_or(ZKError::CircuitNotFound)?.as_ref();
            let proving_key = proving_keys.get(&circuit_id).ok_or(ZKError::CircuitNotFound)?;

            (circuit.clone(), proving_key.clone())
        };

        // Validate witness and public inputs
        if witness.len() != circuit.num_variables {
            return Err(ZKError::InvalidWitness);
        }

        // Convert byte inputs back to FieldElements for proving
        let witness_fe: Vec<crate::zk_engine::groth16::FieldElement> = witness
            .iter()
            .map(|bytes| {
                crate::zk_engine::groth16::FieldElement::from_bytes(bytes.as_slice())
                    .unwrap_or(crate::zk_engine::groth16::FieldElement::zero())
            })
            .collect();
        let public_inputs_fe: Vec<crate::zk_engine::groth16::FieldElement> = public_inputs
            .iter()
            .map(|bytes| {
                crate::zk_engine::groth16::FieldElement::from_bytes(bytes.as_slice())
                    .unwrap_or(crate::zk_engine::groth16::FieldElement::zero())
            })
            .collect();

        // Generate proof
        let proof_data = Groth16Prover::prove(
            &proving_key,
            &circuit,
            &witness_fe,
            &public_inputs_fe,
            circuit_id,
        )?;

        // Calculate proof hash
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

    /// Verify proof
    pub fn verify_proof(&self, proof: &ZKProof) -> Result<bool, ZKError> {
        let start_time = crate::time::timestamp_millis();

        // Check verification cache
        if self.config.enable_verification_cache {
            let cache = self.verification_cache.lock();
            if let Some(&cached_result) = cache.get(&proof.proof_hash) {
                return Ok(cached_result);
            }
        }

        // Get verifying key
        let verifying_key = {
            let verifying_keys = self.verifying_keys.read();
            verifying_keys.get(&proof.circuit_id).ok_or(ZKError::CircuitNotFound)?.clone()
        };

        // Convert public inputs from bytes to FieldElements
        let public_inputs_fe: Vec<crate::zk_engine::groth16::FieldElement> = proof
            .public_inputs
            .iter()
            .map(|bytes| {
                crate::zk_engine::groth16::FieldElement::from_bytes(bytes.as_slice())
                    .unwrap_or(crate::zk_engine::groth16::FieldElement::zero())
            })
            .collect();

        // Verify proof
        let is_valid =
            Groth16Verifier::verify(&verifying_key, &proof.proof_data, &public_inputs_fe)?;

        // Update cache
        if self.config.enable_verification_cache {
            let mut cache = self.verification_cache.lock();
            cache.insert(proof.proof_hash, is_valid);

            // Limit cache size
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

        crate::log::info!(
            "Verified proof for circuit {} in {}ms (result: {})",
            proof.circuit_id,
            verification_time,
            is_valid
        );

        Ok(is_valid)
    }

    /// Batch verify multiple proofs for efficiency
    pub fn batch_verify_proofs(&self, proofs: &[ZKProof]) -> Result<Vec<bool>, ZKError> {
        let start_time = crate::time::timestamp_millis();
        let mut results = Vec::with_capacity(proofs.len());

        // Group proofs by circuit ID for batch processing
        let mut proofs_by_circuit: BTreeMap<u32, Vec<&ZKProof>> = BTreeMap::new();
        for proof in proofs {
            proofs_by_circuit.entry(proof.circuit_id).or_insert_with(Vec::new).push(proof);
        }

        // Process each circuit's proofs in batch
        for (circuit_id, circuit_proofs) in proofs_by_circuit {
            let verifying_key = {
                let verifying_keys = self.verifying_keys.read();
                verifying_keys.get(&circuit_id).ok_or(ZKError::CircuitNotFound)?.clone()
            };

            for proof in circuit_proofs {
                // Convert public inputs from bytes to FieldElements
                let public_inputs_fe: Vec<crate::zk_engine::groth16::FieldElement> = proof
                    .public_inputs
                    .iter()
                    .map(|bytes| {
                        crate::zk_engine::groth16::FieldElement::from_bytes(bytes.as_slice())
                            .unwrap_or(crate::zk_engine::groth16::FieldElement::zero())
                    })
                    .collect();

                let is_valid =
                    Groth16Verifier::verify(&verifying_key, &proof.proof_data, &public_inputs_fe)?;
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

    /// Get engine statistics
    pub fn get_stats(&self) -> &ZKStats {
        &self.stats
    }

    /// Clean up verification cache and unused circuits
    pub fn cleanup(&self) {
        // Clean verification cache
        let mut cache = self.verification_cache.lock();
        let now = crate::time::timestamp_millis();
        cache.retain(|_, _| true); // Keep all for now, could add TTL

        // Log cleanup
        crate::log::info!("ZK engine cleanup completed");
    }

    /// Serialize proof to bytes
    pub fn serialize_proof(&self, proof: &ZKProof) -> Vec<u8> {
        let mut serialized = Vec::new();

        // Circuit ID (4 bytes)
        serialized.extend_from_slice(&proof.circuit_id.to_le_bytes());

        // Proof data length (4 bytes) + data
        let proof_bytes = proof.proof_data.serialize();
        serialized.extend_from_slice(&(proof_bytes.len() as u32).to_le_bytes());
        serialized.extend_from_slice(&proof_bytes);

        // Number of public inputs (4 bytes)
        serialized.extend_from_slice(&(proof.public_inputs.len() as u32).to_le_bytes());

        // Public inputs
        for input in &proof.public_inputs {
            serialized.extend_from_slice(&(input.len() as u32).to_le_bytes());
            serialized.extend_from_slice(input);
        }

        // Proof hash (32 bytes)
        serialized.extend_from_slice(&proof.proof_hash);

        // Creation timestamp (8 bytes)
        serialized.extend_from_slice(&proof.created_at.to_le_bytes());

        serialized
    }

    /// Deserialize proof from bytes
    pub fn deserialize_proof(&self, data: &[u8]) -> Result<ZKProof, ZKError> {
        if data.len() < 48 {
            // Minimum size
            return Err(ZKError::InvalidProof);
        }

        let mut offset = 0;

        // Circuit ID
        let circuit_id = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
        offset += 4;

        // Proof data
        let proof_len = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        if offset + proof_len > data.len() {
            return Err(ZKError::InvalidProof);
        }

        let proof_bytes = &data[offset..offset + proof_len];
        let proof_data = groth16::Proof::deserialize(proof_bytes)?;
        offset += proof_len;

        // Public inputs
        if offset + 4 > data.len() {
            return Err(ZKError::InvalidProof);
        }

        let num_inputs = u32::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
        ]) as usize;
        offset += 4;

        let mut public_inputs = Vec::with_capacity(num_inputs);
        for _ in 0..num_inputs {
            if offset + 4 > data.len() {
                return Err(ZKError::InvalidProof);
            }

            let input_len = u32::from_le_bytes([
                data[offset],
                data[offset + 1],
                data[offset + 2],
                data[offset + 3],
            ]) as usize;
            offset += 4;

            if offset + input_len > data.len() {
                return Err(ZKError::InvalidProof);
            }

            let input = data[offset..offset + input_len].to_vec();
            public_inputs.push(input);
            offset += input_len;
        }

        // Proof hash
        if offset + 32 > data.len() {
            return Err(ZKError::InvalidProof);
        }

        let mut proof_hash = [0u8; 32];
        proof_hash.copy_from_slice(&data[offset..offset + 32]);
        offset += 32;

        // Creation timestamp
        if offset + 8 > data.len() {
            return Err(ZKError::InvalidProof);
        }

        let created_at = u64::from_le_bytes([
            data[offset],
            data[offset + 1],
            data[offset + 2],
            data[offset + 3],
            data[offset + 4],
            data[offset + 5],
            data[offset + 6],
            data[offset + 7],
        ]);

        Ok(ZKProof { circuit_id, proof_data, public_inputs, proof_hash, created_at })
    }
}

/// Initialize global ZK engine
pub fn init_zk_engine() -> Result<(), ZKError> {
    let config = ZKConfig::default();
    let engine = ZKEngine::new(config)?;

    ZK_ENGINE.call_once(|| engine);

    // Initialize attestation manager
    init_attestation_manager()?;

    crate::log::info!("ZK Engine and attestation manager initialized successfully");
    Ok(())
}

/// Get global ZK engine
pub fn get_zk_engine() -> &'static ZKEngine {
    ZK_ENGINE.get().expect("ZK Engine not initialized")
}

/// Get global ZK engine for static access (used by attestation)
pub fn get_zk_engine_static() -> Option<&'static ZKEngine> {
    ZK_ENGINE.get()
}

/// Convenience function for circuit compilation
pub fn compile_circuit(constraints: Vec<Constraint>, num_witnesses: usize) -> Result<u32, ZKError> {
    get_zk_engine().compile_circuit(constraints, num_witnesses)
}

/// Convenience function for proof generation  
pub fn generate_proof(
    circuit_id: u32,
    witness: Vec<Vec<u8>>,
    public_inputs: Vec<Vec<u8>>,
) -> Result<ZKProof, ZKError> {
    get_zk_engine().generate_proof(circuit_id, witness, public_inputs)
}

/// Convenience function for proof verification
pub fn verify_proof(proof: &ZKProof) -> Result<bool, ZKError> {
    get_zk_engine().verify_proof(proof)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_zk_engine_initialization() {
        let config = ZKConfig::default();
        let engine = ZKEngine::new(config);
        assert!(engine.is_ok());
    }

    #[test]
    fn test_proof_serialization() {
        let proof = ZKProof {
            circuit_id: 123,
            proof_data: vec![1, 2, 3, 4],
            public_inputs: vec![vec![5, 6], vec![7, 8, 9]],
            proof_hash: [0xAB; 32],
            created_at: 1234567890,
        };

        let config = ZKConfig::default();
        let engine = ZKEngine::new(config).unwrap();

        let serialized = engine.serialize_proof(&proof);
        let deserialized = engine.deserialize_proof(&serialized).unwrap();

        assert_eq!(proof.circuit_id, deserialized.circuit_id);
        assert_eq!(proof.proof_data, deserialized.proof_data);
        assert_eq!(proof.public_inputs, deserialized.public_inputs);
        assert_eq!(proof.proof_hash, deserialized.proof_hash);
        assert_eq!(proof.created_at, deserialized.created_at);
    }
}
