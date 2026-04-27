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

extern crate alloc;

use crate::crypto::hash::blake3::blake3_hash;
use alloc::collections::BTreeMap;
use alloc::vec::Vec;
use spin::RwLock;

pub struct VerificationCache {
    cache: RwLock<BTreeMap<[u8; 32], bool>>,
}

pub fn compute_cache_key(
    circuit_id: u32,
    proof_hash: &[u8; 32],
    public_inputs: &[Vec<u8>],
) -> [u8; 32] {
    let mut hasher_input = Vec::with_capacity(36 + public_inputs.len() * 32);
    hasher_input.extend_from_slice(&circuit_id.to_le_bytes());
    hasher_input.extend_from_slice(proof_hash);
    for input in public_inputs {
        hasher_input.extend_from_slice(input);
    }
    blake3_hash(&hasher_input)
}

impl VerificationCache {
    pub fn new() -> Self {
        Self { cache: RwLock::new(BTreeMap::new()) }
    }

    pub fn get(&self, cache_key: &[u8; 32]) -> Option<bool> {
        self.cache.read().get(cache_key).copied()
    }

    pub fn insert(&self, cache_key: [u8; 32], result: bool) {
        self.cache.write().insert(cache_key, result);
    }

    pub fn len(&self) -> usize {
        self.cache.read().len()
    }

    pub fn evict_oldest(&self, count: usize) {
        let mut cache = self.cache.write();
        let keys: Vec<_> = cache.keys().take(count).cloned().collect();
        for key in keys {
            cache.remove(&key);
        }
    }

    pub fn clear(&self) {
        self.cache.write().clear();
    }
}

impl Default for VerificationCache {
    fn default() -> Self {
        Self::new()
    }
}
