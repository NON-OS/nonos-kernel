//! Groth16 Proof Verification Implementation
//!
//! This module implements the verification algorithm for Groth16 proofs.
//! Verification requires only the verifying key and public inputs, making
//! it efficient for on-chain or resource-constrained verification.

use super::groth16::{FieldElement, G1Point, G2Point, Pairing, Proof};
use super::setup::VerifyingKey;
use crate::zk_engine::ZKError;
use alloc::{vec, vec::Vec};

/// Groth16 proof verifier
pub struct Groth16Verifier {
    verifying_key: VerifyingKey,
}

impl Groth16Verifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifying_key }
    }

    /// Verify a Groth16 proof with public inputs
    pub fn verify(&self, proof: &Proof, public_inputs: &[FieldElement]) -> Result<bool, ZKError> {
        // Validate inputs
        self.validate_inputs(proof, public_inputs)?;

        // Compute verification equation
        self.verify_proof_equation(proof, public_inputs)
    }

    /// Validate proof and public inputs
    fn validate_inputs(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<(), ZKError> {
        // Check proof components are not identity
        if proof.a.is_identity() {
            return Err(ZKError::VerificationFailed);
        }

        if proof.b.is_identity() {
            return Err(ZKError::VerificationFailed);
        }

        if proof.c.is_identity() {
            return Err(ZKError::VerificationFailed);
        }

        // Check public inputs length
        if public_inputs.len() + 1 != self.verifying_key.ic.len() {
            return Err(ZKError::VerificationFailed);
        }

        // Validate that proof points are on curve
        if !proof.a.is_on_curve() || !proof.c.is_on_curve() {
            return Err(ZKError::VerificationFailed);
        }

        if !proof.b.is_on_curve() {
            return Err(ZKError::VerificationFailed);
        }

        Ok(())
    }

    /// Verify the main proof equation using pairings
    fn verify_proof_equation(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<bool, ZKError> {
        // Compute vk_x = IC[0] + sum(public_inputs[i] * IC[i+1])
        let vk_x = self.compute_vk_x(public_inputs)?;

        // Verification equation:
        // e(A, B) = e(α, β) * e(vk_x, γ) * e(C, δ)
        //
        // Rearranged as:
        // e(A, B) * e(-α, β) * e(-vk_x, γ) * e(-C, δ) = 1

        let pairing1 = Pairing::compute(&proof.a, &proof.b);
        let pairing2 =
            Pairing::compute(&self.verifying_key.alpha_g1.negate(), &self.verifying_key.beta_g2);
        let pairing3 = Pairing::compute(&vk_x.negate(), &self.verifying_key.gamma_g2);
        let pairing4 = Pairing::compute(&proof.c.negate(), &self.verifying_key.delta_g2);

        // Multiply all pairings
        let result = pairing1.multiply(&pairing2).multiply(&pairing3).multiply(&pairing4);

        // Check if result equals identity in GT
        Ok(result.is_identity())
    }

    /// Compute vk_x = IC[0] + sum(public_inputs[i] * IC[i+1])
    fn compute_vk_x(&self, public_inputs: &[FieldElement]) -> Result<G1Point, ZKError> {
        if self.verifying_key.ic.is_empty() {
            return Err(ZKError::VerificationFailed);
        }

        let mut vk_x = self.verifying_key.ic[0];

        for (i, &input) in public_inputs.iter().enumerate() {
            if i + 1 >= self.verifying_key.ic.len() {
                return Err(ZKError::VerificationFailed);
            }

            let term = self.verifying_key.ic[i + 1].scalar_mul(&input.limbs);
            vk_x = vk_x.add(&term);
        }

        Ok(vk_x)
    }

    /// Batch verify multiple proofs (more efficient than individual
    /// verification)
    pub fn batch_verify(
        &self,
        proofs: &[Proof],
        public_inputs: &[Vec<FieldElement>],
    ) -> Result<bool, ZKError> {
        if proofs.len() != public_inputs.len() {
            return Err(ZKError::VerificationFailed);
        }

        if proofs.is_empty() {
            return Ok(true);
        }

        // For simplicity, verify each proof individually
        // Real batch verification would use randomization for efficiency
        for (proof, inputs) in proofs.iter().zip(public_inputs.iter()) {
            if !self.verify(proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    /// Optimized verification for proofs with no public inputs
    pub fn verify_no_inputs(&self, proof: &Proof) -> Result<bool, ZKError> {
        self.verify(proof, &[])
    }

    /// Verify proof with timing information for performance analysis
    pub fn verify_with_timing(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<(bool, u64), ZKError> {
        let start_time = crate::time::timestamp_millis();
        let result = self.verify(proof, public_inputs)?;
        let end_time = crate::time::timestamp_millis();

        Ok((result, end_time - start_time))
    }
}

/// Advanced verification features
impl Groth16Verifier {
    /// Verify proof and return detailed error information
    pub fn verify_detailed(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> VerificationResult {
        // Validate basic structure
        if let Err(e) = self.validate_inputs(proof, public_inputs) {
            return VerificationResult {
                valid: false,
                error: Some(e),
                timing_ms: 0,
                pairing_checks: 0,
            };
        }

        let start_time = crate::time::timestamp_millis();

        // Perform verification
        let valid = match self.verify_proof_equation(proof, public_inputs) {
            Ok(result) => result,
            Err(e) => {
                return VerificationResult {
                    valid: false,
                    error: Some(e),
                    timing_ms: crate::time::timestamp_millis() - start_time,
                    pairing_checks: 4, // We performed 4 pairing computations
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

    /// Pre-process verifying key for faster verification
    pub fn preprocess_vk(&mut self) -> Result<(), ZKError> {
        // In a real implementation, this would precompute pairing-friendly
        // representations of the verifying key elements
        // For now, just validate the key
        self.verifying_key.verify_key()?;
        Ok(())
    }

    /// Verify proof against a specific circuit identifier
    pub fn verify_for_circuit(
        &self,
        proof: &Proof,
        public_inputs: &[FieldElement],
        expected_circuit_id: u32,
    ) -> Result<bool, ZKError> {
        if proof.circuit_id != expected_circuit_id {
            return Err(ZKError::CircuitNotFound);
        }

        self.verify(proof, public_inputs)
    }
}

/// Detailed verification result with diagnostics
#[derive(Debug)]
pub struct VerificationResult {
    pub valid: bool,
    pub error: Option<ZKError>,
    pub timing_ms: u64,
    pub pairing_checks: u32,
}

impl VerificationResult {
    pub fn success(timing_ms: u64) -> Self {
        Self { valid: true, error: None, timing_ms, pairing_checks: 4 }
    }

    pub fn failure(error: ZKError, timing_ms: u64) -> Self {
        Self { valid: false, error: Some(error), timing_ms, pairing_checks: 0 }
    }
}

/// Verification key management
pub struct VerificationKeyManager {
    keys: alloc::collections::BTreeMap<u32, VerifyingKey>,
}

impl VerificationKeyManager {
    pub fn new() -> Self {
        Self { keys: alloc::collections::BTreeMap::new() }
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

/// Proof aggregation for multiple proofs (experimental)
pub struct ProofAggregator;

impl ProofAggregator {
    /// Aggregate multiple proofs into a single proof (placeholder
    /// implementation)
    pub fn aggregate_proofs(proofs: &[Proof]) -> Result<Proof, ZKError> {
        if proofs.is_empty() {
            return Err(ZKError::VerificationFailed);
        }

        // This is a placeholder - real aggregation would combine proofs
        // cryptographically For now, return the first proof
        Ok(proofs[0].clone())
    }

    /// Verify an aggregated proof
    pub fn verify_aggregated(
        verifier: &Groth16Verifier,
        aggregated_proof: &Proof,
        all_public_inputs: &[Vec<FieldElement>],
    ) -> Result<bool, ZKError> {
        // Placeholder implementation
        if all_public_inputs.is_empty() {
            return verifier.verify_no_inputs(aggregated_proof);
        }

        // For now, just verify against the first set of inputs
        verifier.verify(aggregated_proof, &all_public_inputs[0])
    }
}

/// Verification caching for repeated verifications
pub struct VerificationCache {
    cache: alloc::collections::BTreeMap<[u8; 32], bool>,
    max_size: usize,
}

impl VerificationCache {
    pub fn new(max_size: usize) -> Self {
        Self { cache: alloc::collections::BTreeMap::new(), max_size }
    }

    pub fn verify_cached(
        &mut self,
        verifier: &Groth16Verifier,
        proof: &Proof,
        public_inputs: &[FieldElement],
    ) -> Result<bool, ZKError> {
        let cache_key = self.compute_cache_key(proof, public_inputs);

        if let Some(&cached_result) = self.cache.get(&cache_key) {
            return Ok(cached_result);
        }

        let result = verifier.verify(proof, public_inputs)?;

        // Add to cache if not full
        if self.cache.len() < self.max_size {
            self.cache.insert(cache_key, result);
        }

        Ok(result)
    }

    fn compute_cache_key(&self, proof: &Proof, public_inputs: &[FieldElement]) -> [u8; 32] {
        use crate::crypto::hash::blake3_hash;

        let mut hasher_input = Vec::new();

        // Add proof components to hash
        hasher_input.extend_from_slice(&proof.a.to_bytes());
        hasher_input.extend_from_slice(&proof.b.to_bytes());
        hasher_input.extend_from_slice(&proof.c.to_bytes());

        // Add public inputs to hash
        for input in public_inputs {
            hasher_input.extend_from_slice(&input.to_bytes());
        }

        blake3_hash(&hasher_input)
    }

    pub fn clear(&mut self) {
        self.cache.clear();
    }

    pub fn cache_size(&self) -> usize {
        self.cache.len()
    }
}

/// Parallel verification for high throughput
pub struct ParallelVerifier {
    verifier: Groth16Verifier,
}

impl ParallelVerifier {
    pub fn new(verifying_key: VerifyingKey) -> Self {
        Self { verifier: Groth16Verifier::new(verifying_key) }
    }

    /// Verify multiple proofs in parallel (simulated for now)
    pub fn verify_parallel(
        &self,
        proofs_and_inputs: &[(Proof, Vec<FieldElement>)],
    ) -> Result<Vec<bool>, ZKError> {
        let mut results = Vec::with_capacity(proofs_and_inputs.len());

        // In a real implementation, this would use actual parallelization
        for (proof, inputs) in proofs_and_inputs {
            let result = self.verifier.verify(proof, inputs)?;
            results.push(result);
        }

        Ok(results)
    }

    /// Get verification statistics
    pub fn get_stats(&self) -> VerificationStats {
        VerificationStats {
            total_verifications: 0, // Would track in real implementation
            successful_verifications: 0,
            failed_verifications: 0,
            avg_verification_time_ms: 0,
        }
    }
}

/// Verification performance statistics
#[derive(Debug, Default)]
pub struct VerificationStats {
    pub total_verifications: u64,
    pub successful_verifications: u64,
    pub failed_verifications: u64,
    pub avg_verification_time_ms: u64,
}

/// Specialized verifiers for common proof types
pub mod specialized {
    use super::*;

    /// Verifier optimized for signature verification proofs
    pub struct SignatureVerifier(Groth16Verifier);

    impl SignatureVerifier {
        pub fn new(vk: VerifyingKey) -> Self {
            Self(Groth16Verifier::new(vk))
        }

        pub fn verify_signature_proof(
            &self,
            proof: &Proof,
            message_hash: &[u8; 32],
            public_key: &[u8; 32],
        ) -> Result<bool, ZKError> {
            // Convert to field elements
            let public_inputs = vec![
                FieldElement::from_bytes(message_hash)?,
                FieldElement::from_bytes(public_key)?,
            ];

            self.0.verify(proof, &public_inputs)
        }
    }

    /// Verifier optimized for range proofs
    pub struct RangeProofVerifier(Groth16Verifier);

    impl RangeProofVerifier {
        pub fn new(vk: VerifyingKey) -> Self {
            Self(Groth16Verifier::new(vk))
        }

        pub fn verify_range_proof(
            &self,
            proof: &Proof,
            commitment: &FieldElement,
            min_value: u64,
            max_value: u64,
        ) -> Result<bool, ZKError> {
            let public_inputs = vec![
                *commitment,
                FieldElement::from_u64(min_value),
                FieldElement::from_u64(max_value),
            ];

            self.0.verify(proof, &public_inputs)
        }
    }
}
