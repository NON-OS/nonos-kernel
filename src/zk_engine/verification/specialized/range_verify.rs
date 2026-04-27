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

use super::range_check::{verify_commitment_structure, verify_inner_product};
use super::range_parse::parse_proof;
use super::range_types::RangeProof;
use alloc::vec::Vec;

pub struct RangeProofVerifier;

impl RangeProofVerifier {
    pub fn verify(commitment: &[u8; 32], proof: &[u8], min: u64, max: u64) -> bool {
        if min > max {
            return false;
        }
        let range_proof = match parse_proof(proof) {
            Some(p) => p,
            None => return false,
        };
        let range_size = max.saturating_sub(min);
        let required_bits = if range_size == 0 { 1 } else { 64 - range_size.leading_zeros() };
        if range_proof.bit_length < required_bits {
            return false;
        }
        let challenge = Self::compute_challenge(commitment, &range_proof);
        if !verify_inner_product(&range_proof, &challenge) {
            return false;
        }
        if !verify_commitment_structure(commitment, &range_proof, &challenge) {
            return false;
        }
        true
    }

    pub fn compute_challenge(commitment: &[u8; 32], proof: &RangeProof) -> [u8; 32] {
        let mut transcript = Vec::with_capacity(256);
        transcript.extend_from_slice(b"NONOS-RangeProof-v1");
        transcript.extend_from_slice(commitment);
        transcript.extend_from_slice(&proof.a);
        transcript.extend_from_slice(&proof.s);
        transcript.extend_from_slice(&proof.t1);
        transcript.extend_from_slice(&proof.t2);
        transcript.extend_from_slice(&proof.bit_length.to_le_bytes());
        crate::crypto::hash::blake3::blake3_hash(&transcript)
    }

    pub fn verify_simple(commitment: &[u8; 32], proof: &[u8], bit_length: u32) -> bool {
        if bit_length == 0 || bit_length > 64 {
            return false;
        }
        let max = if bit_length >= 64 { u64::MAX } else { (1u64 << bit_length) - 1 };
        Self::verify(commitment, proof, 0, max)
    }
}
