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
use alloc::{vec::Vec, collections::BTreeMap, sync::Arc};
use core::sync::atomic::{AtomicU64, Ordering};
use spin::Mutex;
use super::types::{QuantumAlgorithm, QuantumKey, QuantumKeyRotation, QuantumKeyRotationPolicy};
use super::pq_ops::generate_pq_keypair;

pub struct QuantumKeyVault {
    keys: Mutex<BTreeMap<[u8; 32], Arc<QuantumKey>>>,
    rotations: Mutex<Vec<QuantumKeyRotation>>,
    rotation_policy: QuantumKeyRotationPolicy,
}

impl QuantumKeyVault {
    pub fn new() -> Self {
        Self {
            keys: Mutex::new(BTreeMap::new()),
            rotations: Mutex::new(Vec::new()),
            rotation_policy: QuantumKeyRotationPolicy::default(),
        }
    }

    pub fn generate_key(&self, algo: QuantumAlgorithm, lifetime_secs: u64) -> Option<Arc<QuantumKey>> {
        let (public, secret) = match generate_pq_keypair(&algo) {
            Ok(kp) => kp,
            Err(_) => return None,
        };
        let key_id = crate::crypto::hash::blake3_hash(&public);
        let now = crate::time::timestamp_millis() / 1000;
        let key = Arc::new(QuantumKey {
            algo,
            key_id,
            public,
            secret,
            created_at: now,
            expires_at: now + lifetime_secs,
            usage_count: AtomicU64::new(0),
        });
        self.keys.lock().insert(key_id, key.clone());
        Some(key)
    }

    pub fn rotate_key(&self, key_id: &[u8; 32], reason: &str) -> Option<Arc<QuantumKey>> {
        let keys = self.keys.lock();
        let old_key = keys.get(key_id)?.clone();
        let new_key = self.generate_key(old_key.algo.clone(), old_key.expires_at - old_key.created_at)?;
        self.rotations.lock().push(QuantumKeyRotation {
            old_key_id: *key_id,
            new_key_id: new_key.key_id,
            rotated_at: crate::time::timestamp_millis() / 1000,
            reason: reason.into(),
        });
        Some(new_key)
    }

    pub fn get_key(&self, key_id: &[u8; 32]) -> Option<Arc<QuantumKey>> {
        self.keys.lock().get(key_id).cloned()
    }

    pub fn cleanup(&self) {
        let now = crate::time::timestamp_millis() / 1000;
        self.keys.lock().retain(|_, k| {
            let expired = self.rotation_policy.enforce_expiry && now > k.expires_at;
            let overused = k.usage_count.load(Ordering::Relaxed) > self.rotation_policy.max_usage;
            !(expired || overused)
        });
    }
}
