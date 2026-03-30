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

pub struct MerkleVerifier;

impl MerkleVerifier {
    pub fn verify_membership(
        root: &[u8; 32],
        leaf: &[u8; 32],
        proof: &[[u8; 32]],
        index: u64,
    ) -> bool {
        if proof.is_empty() {
            return leaf == root;
        }
        if proof.len() > 64 {
            return false;
        }
        let mut current = *leaf;
        let mut idx = index;
        for sibling in proof {
            let is_right = (idx & 1) == 1;
            let mut combined = [0u8; 64];
            if is_right {
                combined[..32].copy_from_slice(sibling);
                combined[32..].copy_from_slice(&current);
            } else {
                combined[..32].copy_from_slice(&current);
                combined[32..].copy_from_slice(sibling);
            }
            current = crate::crypto::hash::blake3::blake3_hash(&combined);
            idx >>= 1;
        }
        current == *root
    }
}
