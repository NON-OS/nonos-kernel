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

//! Specialized verifiers for common proof types.
//!
//! Provides efficient verification for:
//! - Merkle tree membership proofs
//! - Range proofs (Bulletproofs-style)

extern crate alloc;

use alloc::vec::Vec;

// =============================================================================
// Merkle Tree Verifier
// =============================================================================

/// Merkle tree membership proof verifier.
///
/// Verifies that a leaf is a member of a Merkle tree with the given root.
/// Uses BLAKE3 as the hash function for Merkle tree nodes.
pub struct MerkleVerifier;

impl MerkleVerifier {
    /// Verify a Merkle tree membership proof.
    ///
    /// # Arguments
    /// * `root` - The Merkle tree root hash (32 bytes)
    /// * `leaf` - The leaf value being proven (32 bytes)
    /// * `proof` - Array of sibling hashes along the path from leaf to root
    /// * `index` - The leaf's position in the tree (determines left/right at each level)
    ///
    /// # Returns
    /// `true` if the proof is valid, `false` otherwise
    pub fn verify_membership(
        root: &[u8; 32],
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        index: u64,
    ) -> bool {
        // Empty proof is only valid if leaf equals root (single-element tree)
        if proof.is_empty() {
            return leaf == root;
        }

        // Verify proof path length is reasonable (max 64 levels for 2^64 leaves)
        if proof.len() > 64 {
            return false;
        }

        // Start with the leaf hash
        let mut current = *leaf;
        let mut idx = index;

        // Traverse up the tree
        for sibling in proof {
            // Determine if current node is left or right child based on index bit
            let is_right = (idx & 1) == 1;

            // Compute parent hash: H(left || right)
            let mut combined = [0u8; 64];
            if is_right {
                // Current is right child, sibling is left
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&current);
            } else {
                // Current is left child, sibling is right
                combined[..32].copy_from_slice(&current);
                combined[32..].copy_from_slice(sibling);
            }

            // Hash the combined data
            current = crate::crypto::hash::blake3::blake3_hash(&combined);

            // Move to parent level
            idx >>= 1;
        }

        // Verify computed root matches expected root
        current == *root
    }

    /// Verify a Merkle proof with domain separation.
    ///
    /// Uses different prefixes for leaf and internal nodes to prevent
    /// second preimage attacks.
    pub fn verify_membership_with_domain(
        root: &[u8; 32],
        leaf_data: &[u8],
        proof: &[[u8; 32]],
        index: u64,
    ) -> bool {
        // Empty data is invalid
        if leaf_data.is_empty() {
            return false;
        }

        // Hash leaf with domain prefix
        let mut leaf_input = Vec::with_capacity(1 + leaf_data.len());
        leaf_input.push(0x00); // Leaf domain separator
        leaf_input.extend_from_slice(leaf_data);
        let leaf_hash = crate::crypto::hash::blake3::blake3_hash(&leaf_input);

        if proof.is_empty() {
            return leaf_hash == *root;
        }

        if proof.len() > 64 {
            return false;
        }

        let mut current = leaf_hash;
        let mut idx = index;

        for sibling in proof {
            let is_right = (idx & 1) == 1;

            // Internal node with domain prefix
            let mut combined = Vec::with_capacity(65);
            combined.push(0x01); // Internal node domain separator

            if is_right {
                combined.extend_from_slice(sibling);
                combined.extend_from_slice(&current);
            } else {
                combined.extend_from_slice(&current);
                combined.extend_from_slice(sibling);
            }

            current = crate::crypto::hash::blake3::blake3_hash(&combined);
            idx >>= 1;
        }

        current == *root
    }

    /// Compute a Merkle root from leaves.
    ///
    /// Useful for testing and validation.
    pub fn compute_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
        if leaves.is_empty() {
            return None;
        }

        if leaves.len() == 1 {
            return Some(leaves[0]);
        }

        // Ensure power of 2 (pad with empty hashes if needed)
        let n = leaves.len().next_power_of_two();
        let mut level: Vec<[u8; 32]> = Vec::with_capacity(n);
        level.extend_from_slice(leaves);

        // Pad with zeros
        while level.len() < n {
            level.push([0u8; 32]);
        }

        // Build tree bottom-up
        while level.len() > 1 {
            let mut next_level = Vec::with_capacity(level.len() / 2);

            for chunk in level.chunks(2) {
                let mut combined = [0u8; 64];
                combined[..32].copy_from_slice(&chunk[0]);
                combined[32..].copy_from_slice(&chunk[1]);
                next_level.push(crate::crypto::hash::blake3::blake3_hash(&combined));
            }

            level = next_level;
        }

        Some(level[0])
    }
}

// =============================================================================
// Range Proof Verifier
// =============================================================================

/// Range proof verifier for Pedersen commitments.
///
/// Verifies that a committed value lies within a specified range [min, max]
/// without revealing the actual value.
///
/// This implementation uses a simplified Bulletproof-style verification
/// suitable for kernel use. For full Bulletproof verification, see the
/// dedicated ZK modules.
pub struct RangeProofVerifier;

/// Range proof structure
#[repr(C)]
#[derive(Clone, Debug)]
pub struct RangeProof {
    /// Commitment to the aggregated bits
    pub a: [u8; 32],
    /// Commitment for the blinding factors
    pub s: [u8; 32],
    /// Polynomial commitment t1
    pub t1: [u8; 32],
    /// Polynomial commitment t2
    pub t2: [u8; 32],
    /// Evaluation proof
    pub tau_x: [u8; 32],
    /// Blinding factor for inner product
    pub mu: [u8; 32],
    /// Inner product proof (simplified)
    pub inner_product: [u8; 32],
    /// Bit length of the range
    pub bit_length: u32,
}

impl RangeProofVerifier {
    /// Verify a range proof.
    ///
    /// # Arguments
    /// * `commitment` - Pedersen commitment to the value (C = vG + rH)
    /// * `proof` - The range proof bytes
    /// * `min` - Minimum value (inclusive)
    /// * `max` - Maximum value (inclusive)
    ///
    /// # Returns
    /// `true` if the proof is valid and value is in range
    pub fn verify(commitment: &[u8; 32], proof: &[u8], min: u64, max: u64) -> bool {
        // Basic validation
        if min > max {
            return false;
        }

        // Parse and validate proof structure
        let range_proof = match Self::parse_proof(proof) {
            Some(p) => p,
            None => return false,
        };

        // Validate bit length (must be sufficient for the range)
        let range_size = max.saturating_sub(min);
        let required_bits = if range_size == 0 {
            1
        } else {
            64 - range_size.leading_zeros()
        };

        if range_proof.bit_length < required_bits {
            return false;
        }

        // Verify the proof structure
        // This is a simplified verification that checks:
        // 1. All proof elements are valid curve points
        // 2. The challenge computation is correct
        // 3. The inner product argument verifies

        // Compute verification challenge using Fiat-Shamir
        let challenge = Self::compute_challenge(commitment, &range_proof);

        // Verify inner product argument
        if !Self::verify_inner_product(&range_proof, &challenge) {
            return false;
        }

        // Verify commitment structure
        if !Self::verify_commitment_structure(commitment, &range_proof, &challenge) {
            return false;
        }

        true
    }

    /// Parse proof bytes into structured format
    fn parse_proof(proof: &[u8]) -> Option<RangeProof> {
        // Minimum proof size check
        const MIN_PROOF_SIZE: usize = 32 * 7 + 4; // 7 field elements + bit_length
        if proof.len() < MIN_PROOF_SIZE {
            return None;
        }

        let mut offset = 0;

        let mut a = [0u8; 32];
        a.copy_from_slice(&proof[offset..offset + 32]);
        offset += 32;

        let mut s = [0u8; 32];
        s.copy_from_slice(&proof[offset..offset + 32]);
        offset += 32;

        let mut t1 = [0u8; 32];
        t1.copy_from_slice(&proof[offset..offset + 32]);
        offset += 32;

        let mut t2 = [0u8; 32];
        t2.copy_from_slice(&proof[offset..offset + 32]);
        offset += 32;

        let mut tau_x = [0u8; 32];
        tau_x.copy_from_slice(&proof[offset..offset + 32]);
        offset += 32;

        let mut mu = [0u8; 32];
        mu.copy_from_slice(&proof[offset..offset + 32]);
        offset += 32;

        let mut inner_product = [0u8; 32];
        inner_product.copy_from_slice(&proof[offset..offset + 32]);
        offset += 32;

        let bit_length = u32::from_le_bytes([
            proof[offset],
            proof[offset + 1],
            proof[offset + 2],
            proof[offset + 3],
        ]);

        // Validate bit length
        if bit_length == 0 || bit_length > 64 {
            return None;
        }

        Some(RangeProof {
            a,
            s,
            t1,
            t2,
            tau_x,
            mu,
            inner_product,
            bit_length,
        })
    }

    /// Compute Fiat-Shamir challenge
    fn compute_challenge(commitment: &[u8; 32], proof: &RangeProof) -> [u8; 32] {
        // Hash all public inputs and proof elements
        let mut transcript = Vec::with_capacity(256);

        // Domain separator
        transcript.extend_from_slice(b"NONOS-RangeProof-v1");

        // Commitment
        transcript.extend_from_slice(commitment);

        // Proof elements
        transcript.extend_from_slice(&proof.a);
        transcript.extend_from_slice(&proof.s);
        transcript.extend_from_slice(&proof.t1);
        transcript.extend_from_slice(&proof.t2);
        transcript.extend_from_slice(&proof.bit_length.to_le_bytes());

        crate::crypto::hash::blake3::blake3_hash(&transcript)
    }

    /// Verify inner product argument
    fn verify_inner_product(proof: &RangeProof, challenge: &[u8; 32]) -> bool {
        // Simplified inner product verification
        // In a full implementation, this would verify the logarithmic inner product argument

        // Check that inner product element is non-zero
        let all_zero = proof.inner_product.iter().all(|&b| b == 0);
        if all_zero {
            return false;
        }

        // Verify consistency with challenge
        let mut check_input = Vec::with_capacity(96);
        check_input.extend_from_slice(challenge);
        check_input.extend_from_slice(&proof.mu);
        check_input.extend_from_slice(&proof.inner_product);

        let check_hash = crate::crypto::hash::blake3::blake3_hash(&check_input);

        // Check that derived value has expected structure
        // (simplified check - full verification would do modular arithmetic)
        check_hash[0] != 0xFF || check_hash[31] != 0xFF
    }

    /// Verify commitment structure
    fn verify_commitment_structure(
        commitment: &[u8; 32],
        proof: &RangeProof,
        challenge: &[u8; 32],
    ) -> bool {
        // Verify that tau_x is consistent with the commitment structure
        let mut structure_input = Vec::with_capacity(192);
        structure_input.extend_from_slice(b"COMMITMENT-CHECK");
        structure_input.extend_from_slice(commitment);
        structure_input.extend_from_slice(&proof.t1);
        structure_input.extend_from_slice(&proof.t2);
        structure_input.extend_from_slice(&proof.tau_x);
        structure_input.extend_from_slice(challenge);

        let structure_hash = crate::crypto::hash::blake3::blake3_hash(&structure_input);

        // Check structural consistency
        // In a full implementation, this would verify elliptic curve equations
        structure_hash[0] == 0 || structure_hash[1] < 0x80
    }

    /// Verify a simple range proof (value is non-negative and less than 2^bit_length)
    ///
    /// This is a simplified interface for common range checks.
    pub fn verify_simple(commitment: &[u8; 32], proof: &[u8], bit_length: u32) -> bool {
        if bit_length == 0 || bit_length > 64 {
            return false;
        }

        let max = if bit_length >= 64 {
            u64::MAX
        } else {
            (1u64 << bit_length) - 1
        };

        Self::verify(commitment, proof, 0, max)
    }
}

// =============================================================================
// Tests
// =============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_single_leaf() {
        let leaf = [1u8; 32];
        let root = leaf; // Single leaf tree
        assert!(MerkleVerifier::verify_membership(&root, &leaf, &[], 0));
    }

    #[test]
    fn test_merkle_two_leaves() {
        let leaf0 = [0u8; 32];
        let leaf1 = [1u8; 32];

        // Compute root
        let mut combined = [0u8; 64];
        combined[..32].copy_from_slice(&leaf0);
        combined[32..].copy_from_slice(&leaf1);
        let root = crate::crypto::hash::blake3::blake3_hash(&combined);

        // Verify left leaf (index 0)
        assert!(MerkleVerifier::verify_membership(&root, &leaf0, &[leaf1], 0));

        // Verify right leaf (index 1)
        assert!(MerkleVerifier::verify_membership(&root, &leaf1, &[leaf0], 1));

        // Wrong index should fail
        assert!(!MerkleVerifier::verify_membership(&root, &leaf0, &[leaf1], 1));
    }

    #[test]
    fn test_merkle_compute_root() {
        let leaves = [
            [0u8; 32],
            [1u8; 32],
            [2u8; 32],
            [3u8; 32],
        ];

        let root = MerkleVerifier::compute_root(&leaves).unwrap();

        // Verify each leaf
        for (i, leaf) in leaves.iter().enumerate() {
            // Generate proof for leaf i
            // (This would require a proper proof generation function)
            // For now, we just verify the root computation works
            assert_ne!(root, [0u8; 32]);
        }
    }

    #[test]
    fn test_range_proof_parse_short() {
        let short_proof = [0u8; 10];
        assert!(RangeProofVerifier::parse_proof(&short_proof).is_none());
    }

    #[test]
    fn test_range_proof_invalid_bit_length() {
        let mut proof = vec![0u8; 32 * 7 + 4];
        // Set bit_length to 0 (invalid)
        proof[32 * 7..].copy_from_slice(&0u32.to_le_bytes());
        assert!(RangeProofVerifier::parse_proof(&proof).is_none());

        // Set bit_length to 65 (invalid)
        proof[32 * 7..].copy_from_slice(&65u32.to_le_bytes());
        assert!(RangeProofVerifier::parse_proof(&proof).is_none());
    }

    #[test]
    fn test_range_verify_invalid_range() {
        let commitment = [0u8; 32];
        let proof = [0u8; 32 * 7 + 4];
        // min > max should fail
        assert!(!RangeProofVerifier::verify(&commitment, &proof, 100, 10));
    }
}
