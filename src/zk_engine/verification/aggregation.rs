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

//! Proof aggregation for batch verification.

use alloc::vec::Vec;
use crate::zk_engine::groth16::{FieldElement, Proof};
use crate::zk_engine::ZKError;
use super::verifier::Groth16Verifier;

/// Proof aggregation for multiple proofs using random linear combination
pub struct ProofAggregator {
    challenge_seed: [u8; 32],
}

impl ProofAggregator {
    pub fn new() -> Self {
        Self {
            challenge_seed: [0u8; 32],
        }
    }

    pub fn set_challenge_seed(&mut self, seed: [u8; 32]) {
        self.challenge_seed = seed;
    }

    fn generate_challenges(seed: &[u8; 32], count: usize) -> Vec<FieldElement> {
        use crate::crypto::hash::sha256;

        let mut challenges = Vec::with_capacity(count);
        let mut current_hash = *seed;

        for i in 0..count {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(&current_hash);
            input[32..40].copy_from_slice(&(i as u64).to_le_bytes());

            current_hash = sha256(&input);

            let challenge = FieldElement::from_bytes(&current_hash)
                .unwrap_or_else(|_| FieldElement::one());
            challenges.push(challenge);

            let next_input = sha256(&current_hash);
            current_hash = next_input;
        }

        challenges
    }

    fn compute_fs_challenge(proofs: &[Proof]) -> [u8; 32] {
        use crate::crypto::hash::sha256;

        let mut hasher_input = Vec::new();

        for proof in proofs {
            hasher_input.extend_from_slice(&proof.a.to_bytes());
            hasher_input.extend_from_slice(&proof.b.to_bytes());
            hasher_input.extend_from_slice(&proof.c.to_bytes());
        }

        sha256(&hasher_input)
    }

    pub fn aggregate_proofs(proofs: &[Proof]) -> Result<Proof, ZKError> {
        if proofs.is_empty() {
            return Err(ZKError::VerificationFailed);
        }

        if proofs.len() == 1 {
            return Ok(proofs[0].clone());
        }

        let fs_challenge = Self::compute_fs_challenge(proofs);
        let challenges = Self::generate_challenges(&fs_challenge, proofs.len());

        let mut a_agg = proofs[0].a.scalar_mul(&challenges[0].limbs);
        let mut b_agg = proofs[0].b.scalar_mul(&challenges[0].limbs);
        let mut c_agg = proofs[0].c.scalar_mul(&challenges[0].limbs);

        for (i, proof) in proofs.iter().enumerate().skip(1) {
            let a_term = proof.a.scalar_mul(&challenges[i].limbs);
            let b_term = proof.b.scalar_mul(&challenges[i].limbs);
            let c_term = proof.c.scalar_mul(&challenges[i].limbs);

            a_agg = a_agg.add(&a_term);
            b_agg = b_agg.add(&b_term);
            c_agg = c_agg.add(&c_term);
        }

        Ok(Proof {
            a: a_agg,
            b: b_agg,
            c: c_agg,
            circuit_id: proofs[0].circuit_id,
        })
    }

    pub fn batch_verify(
        verifier: &Groth16Verifier,
        proofs: &[Proof],
        all_public_inputs: &[Vec<FieldElement>],
    ) -> Result<bool, ZKError> {
        if proofs.len() != all_public_inputs.len() {
            return Err(ZKError::VerificationFailed);
        }

        if proofs.is_empty() {
            return Ok(true);
        }

        // For now, verify each proof individually
        for (proof, inputs) in proofs.iter().zip(all_public_inputs.iter()) {
            if !verifier.verify(proof, inputs)? {
                return Ok(false);
            }
        }

        Ok(true)
    }
}

impl Default for ProofAggregator {
    fn default() -> Self {
        Self::new()
    }
}
