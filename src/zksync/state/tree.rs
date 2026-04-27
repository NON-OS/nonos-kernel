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

use crate::crypto::sha256;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;

const TREE_DEPTH: usize = 256;

#[derive(Clone, Debug)]
pub struct SparseMerkleTree {
    nodes: BTreeMap<[u8; 32], [u8; 32]>,
    leaves: BTreeMap<[u8; 32], [u8; 32]>,
    root: [u8; 32],
    empty_hashes: [[u8; 32]; TREE_DEPTH + 1],
}

impl SparseMerkleTree {
    pub fn new() -> Self {
        let empty_hashes = Self::compute_empty_hashes();
        Self {
            nodes: BTreeMap::new(),
            leaves: BTreeMap::new(),
            root: empty_hashes[TREE_DEPTH],
            empty_hashes,
        }
    }

    fn compute_empty_hashes() -> [[u8; 32]; TREE_DEPTH + 1] {
        let mut hashes = [[0u8; 32]; TREE_DEPTH + 1];
        for i in 1..=TREE_DEPTH {
            let mut preimage = [0u8; 64];
            preimage[..32].copy_from_slice(&hashes[i - 1]);
            preimage[32..].copy_from_slice(&hashes[i - 1]);
            hashes[i] = sha256(&preimage);
        }
        hashes
    }

    pub fn root(&self) -> [u8; 32] {
        self.root
    }

    pub fn get(&self, key: &[u8; 32]) -> Option<[u8; 32]> {
        self.leaves.get(key).copied()
    }

    pub fn insert(&mut self, key: [u8; 32], value: [u8; 32]) {
        self.leaves.insert(key, value);
        self.recompute_root(&key);
    }

    pub fn remove(&mut self, key: &[u8; 32]) -> Option<[u8; 32]> {
        let old = self.leaves.remove(key)?;
        self.recompute_root(key);
        Some(old)
    }

    fn recompute_root(&mut self, key: &[u8; 32]) {
        let mut current_hash = self.leaves.get(key).copied().unwrap_or([0u8; 32]);
        let mut path = *key;
        for depth in 0..TREE_DEPTH {
            let bit = (path[depth / 8] >> (7 - (depth % 8))) & 1;
            let sibling = self.get_sibling(&path, depth);
            let mut preimage = [0u8; 64];
            if bit == 0 {
                preimage[..32].copy_from_slice(&current_hash);
                preimage[32..].copy_from_slice(&sibling);
            } else {
                preimage[..32].copy_from_slice(&sibling);
                preimage[32..].copy_from_slice(&current_hash);
            }
            current_hash = sha256(&preimage);
            path = self.parent_path(&path, depth);
        }
        self.root = current_hash;
    }

    fn get_sibling(&self, _path: &[u8; 32], depth: usize) -> [u8; 32] {
        self.empty_hashes[depth]
    }

    fn parent_path(&self, path: &[u8; 32], _depth: usize) -> [u8; 32] {
        *path
    }

    pub fn proof(&self, key: &[u8; 32]) -> MerkleProof {
        let mut siblings = Vec::with_capacity(TREE_DEPTH);
        for depth in 0..TREE_DEPTH {
            siblings.push(self.get_sibling(key, depth));
        }
        MerkleProof { key: *key, value: self.get(key), siblings }
    }
}

impl Default for SparseMerkleTree {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Clone, Debug)]
pub struct MerkleProof {
    pub key: [u8; 32],
    pub value: Option<[u8; 32]>,
    pub siblings: Vec<[u8; 32]>,
}

impl MerkleProof {
    pub fn verify(&self, root: &[u8; 32]) -> bool {
        let mut hash = self.value.unwrap_or([0u8; 32]);
        for (depth, sibling) in self.siblings.iter().enumerate() {
            let bit = (self.key[depth / 8] >> (7 - (depth % 8))) & 1;
            let mut preimage = [0u8; 64];
            if bit == 0 {
                preimage[..32].copy_from_slice(&hash);
                preimage[32..].copy_from_slice(sibling);
            } else {
                preimage[..32].copy_from_slice(sibling);
                preimage[32..].copy_from_slice(&hash);
            }
            hash = sha256(&preimage);
        }
        &hash == root
    }
}
