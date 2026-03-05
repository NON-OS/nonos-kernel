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

//! Verification result caching.

use spin::RwLock;
use alloc::collections::BTreeMap;

/// Cache for verified proofs.
pub struct VerificationCache {
    cache: RwLock<BTreeMap<[u8; 32], bool>>,
}

impl VerificationCache {
    pub fn new() -> Self {
        Self {
            cache: RwLock::new(BTreeMap::new()),
        }
    }

    pub fn get(&self, proof_hash: &[u8; 32]) -> Option<bool> {
        self.cache.read().get(proof_hash).copied()
    }

    pub fn insert(&self, proof_hash: [u8; 32], result: bool) {
        self.cache.write().insert(proof_hash, result);
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
