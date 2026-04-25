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

use super::merkle::MerkleVerifier;
use alloc::vec::Vec;

impl MerkleVerifier {
    pub fn verify_membership_with_domain(
        root: &[u8; 32],
        leaf_data: &[u8],
        proof: &[[u8; 32]],
        index: u64,
    ) -> bool {
        if leaf_data.is_empty() {
            return false;
        }
        let mut leaf_input = Vec::with_capacity(1 + leaf_data.len());
        leaf_input.push(0x00);
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
            let mut combined = Vec::with_capacity(65);
            combined.push(0x01);
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
}
