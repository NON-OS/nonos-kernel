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

//! Groth16 proof verifier.

use alloc::{vec::Vec, collections::BTreeMap};
use crate::zk_engine::groth16::{FieldElement, G1Point, Pairing, Proof};
use crate::zk_engine::setup::VerifyingKey;
use crate::zk_engine::ZKError;

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
    fn validate_inputs(&self, proof: &Proof, public_inputs: &[FieldElement]) -> Result<(), ZKError> {
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
    fn verify_proof_equation(&self, proof: &Proof, public_inputs: &[FieldElement]) -> Result<bool, ZKError> {
        // Compute vk_x = IC[0] + sum(public_inputs[i] * IC[i+1])
        let vk_x = self.compute_vk_x(public_inputs)?;

        // Verification equation:
        // e(A, B) = e(alpha, beta) * e(vk_x, gamma) * e(C, delta)
        //
        // Rearranged as:
        // e(A, B) * e(-alpha, beta) * e(-vk_x, gamma) * e(-C, delta) = 1

        let pairing1 = Pairing::compute(&proof.a, &proof.b);
        let pairing2 = Pairing::compute(&self.verifying_key.alpha_g1.negate(), &self.verifying_key.beta_g2);
        let pairing3 = Pairing::compute(&vk_x.negate(), &self.verifying_key.gamma_g2);
        let pairing4 = Pairing::compute(&proof.c.negate(), &self.verifying_key.delta_g2);

        // Multiply all pairings
        let result = pairing1.multiply(&pairing2).multiply(&pairing3).multiply(&pairing4);

        // Check if result equals identity in GT
        Ok(result.is_identity())
    }

    /// Compute vk_x = IC[0] + sum(public_inputs[i] * IC[i+1])
    pub fn compute_vk_x(&self, public_inputs: &[FieldElement]) -> Result<G1Point, ZKError> {
        if self.verifying_key.ic.is_empty() {
            return Err(ZKError::VerificationFailed);
        }

        let mut vk_x = self.verifying_key.ic[0];

        for (i, input) in public_inputs.iter().enumerate() {
            if i + 1 >= self.verifying_key.ic.len() {
                return Err(ZKError::VerificationFailed);
            }

            let term = self.verifying_key.ic[i + 1].scalar_mul(&input.limbs);
            vk_x = vk_x.add(&term);
        }

        Ok(vk_x)
    }

    /// Batch verify multiple proofs (more efficient than individual verification)
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
    pub fn verify_with_timing(&self, proof: &Proof, public_inputs: &[FieldElement]) -> Result<(bool, u64), ZKError> {
        let start_time = crate::time::timestamp_millis();
        let result = self.verify(proof, public_inputs)?;
        let end_time = crate::time::timestamp_millis();

        Ok((result, end_time - start_time))
    }

    /// Verify proof and return detailed error information
    pub fn verify_detailed(&self, proof: &Proof, public_inputs: &[FieldElement]) -> VerificationResult {
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
                    pairing_checks: 4,
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
        Self {
            valid: true,
            error: None,
            timing_ms,
            pairing_checks: 4,
        }
    }

    pub fn failure(error: ZKError, timing_ms: u64) -> Self {
        Self {
            valid: false,
            error: Some(error),
            timing_ms,
            pairing_checks: 0,
        }
    }
}

/// Verification key management
pub struct VerificationKeyManager {
    keys: BTreeMap<u32, VerifyingKey>,
}

impl VerificationKeyManager {
    pub fn new() -> Self {
        Self {
            keys: BTreeMap::new(),
        }
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

/// Verification performance statistics
#[derive(Debug, Default)]
pub struct VerificationStats {
    pub total_verifications: u64,
    pub successful_verifications: u64,
    pub failed_verifications: u64,
    pub avg_verification_time_ms: u64,
}
