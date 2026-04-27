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

use super::core::ProofAggregator;
use crate::zk_engine::groth16::{FieldElement, Proof};
use alloc::vec::Vec;

impl ProofAggregator {
    pub(super) fn generate_challenges(seed: &[u8; 32], count: usize) -> Vec<FieldElement> {
        use crate::crypto::hash::sha256;

        let mut challenges = Vec::with_capacity(count);
        let mut current_hash = *seed;

        for i in 0..count {
            let mut input = [0u8; 64];
            input[..32].copy_from_slice(&current_hash);
            input[32..40].copy_from_slice(&(i as u64).to_le_bytes());

            current_hash = sha256(&input);

            let challenge =
                FieldElement::from_bytes(&current_hash).unwrap_or_else(|_| FieldElement::one());
            challenges.push(challenge);

            let next_input = sha256(&current_hash);
            current_hash = next_input;
        }

        challenges
    }

    pub(super) fn compute_fs_challenge(proofs: &[Proof]) -> [u8; 32] {
        use crate::crypto::hash::sha256;

        let mut hasher_input = Vec::new();

        for proof in proofs {
            hasher_input.extend_from_slice(&proof.a.to_bytes());
            hasher_input.extend_from_slice(&proof.b.to_bytes());
            hasher_input.extend_from_slice(&proof.c.to_bytes());
        }

        sha256(&hasher_input)
    }
}
