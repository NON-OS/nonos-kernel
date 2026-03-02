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

use alloc::string::String;
use alloc::vec::Vec;
use super::types::{KeyType, KeyUsage};
use crate::crypto::constant_time::secure_erase;

pub struct KeyEntry {
    pub id: u64,
    pub name: String,
    pub key_type: KeyType,
    pub(super) material: Vec<u8>,
    pub fingerprint: [u8; 32],
    pub usage: KeyUsage,
    pub created_at: u64,
    pub last_used: u64,
    pub expires_at: u64,
    pub rotation_count: u32,
    pub previous_key_id: Option<u64>,
    pub active: bool,
    pub owner_module: u64,
}

impl KeyEntry {
    pub fn new(
        id: u64,
        name: String,
        key_type: KeyType,
        material: Vec<u8>,
        usage: KeyUsage,
        owner: u64,
    ) -> Self {
        let fingerprint = crate::crypto::blake3::blake3_hash(&material);
        let now = crate::time::timestamp_secs();

        Self {
            id,
            name,
            key_type,
            material,
            fingerprint,
            usage,
            created_at: now,
            last_used: 0,
            expires_at: 0,
            rotation_count: 0,
            previous_key_id: None,
            active: true,
            owner_module: owner,
        }
    }

    pub fn touch(&mut self) {
        self.last_used = crate::time::timestamp_secs();
    }

    pub fn secure_clear(&mut self) {
        secure_erase(&mut self.material);
        self.active = false;
    }

    pub fn material(&self) -> &[u8] {
        &self.material
    }
}

impl Drop for KeyEntry {
    fn drop(&mut self) {
        // SAFETY: Key material must be securely erased to prevent memory disclosure
        secure_erase(&mut self.material);
    }
}
