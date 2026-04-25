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
    pub fn compute_root(leaves: &[[u8; 32]]) -> Option<[u8; 32]> {
        if leaves.is_empty() {
            return None;
        }
        if leaves.len() == 1 {
            return Some(leaves[0]);
        }
        let n = leaves.len().next_power_of_two();
        let mut level: Vec<[u8; 32]> = Vec::with_capacity(n);
        level.extend_from_slice(leaves);
        while level.len() < n {
            level.push([0u8; 32]);
        }
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
