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

use alloc::collections::BTreeMap;
use alloc::vec::Vec;

use super::types::{KeyEntry, KeyMetadata, KeyType, Store, StoreError, MAX_KEYS, MAX_KEY_SIZE};

impl Store {
    pub const fn new() -> Self {
        Self { entries: BTreeMap::new(), next_id: 1 }
    }

    pub fn store(
        &mut self,
        key_type: KeyType,
        data: &[u8],
        owner_pid: u32,
        now: u64,
        expires_at: u64,
    ) -> Result<u32, StoreError> {
        if data.is_empty() || data.len() > MAX_KEY_SIZE {
            return Err(StoreError::InvalidArgument);
        }
        if self.entries.len() >= MAX_KEYS {
            return Err(StoreError::Full);
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.entries.insert(
            id,
            KeyEntry {
                key_type,
                data: data.to_vec(),
                owner_pid,
                created_at: now,
                expires_at,
                use_count: 0,
                locked: false,
            },
        );
        Ok(id)
    }

    pub fn retrieve(&mut self, id: u32, caller_pid: u32) -> Result<Vec<u8>, StoreError> {
        let entry = self.entries.get_mut(&id).ok_or(StoreError::NotFound)?;
        if entry.owner_pid != caller_pid {
            return Err(StoreError::AccessDenied);
        }
        if entry.locked {
            return Err(StoreError::Locked);
        }
        entry.use_count = entry.use_count.saturating_add(1);
        Ok(entry.data.clone())
    }

    pub fn delete(&mut self, id: u32, caller_pid: u32) -> Result<(), StoreError> {
        let entry = self.entries.get(&id).ok_or(StoreError::NotFound)?;
        if entry.owner_pid != caller_pid {
            return Err(StoreError::AccessDenied);
        }
        let mut removed = self.entries.remove(&id).unwrap();
        for byte in removed.data.iter_mut() {
            *byte = 0;
        }
        Ok(())
    }

    pub fn lock(&mut self, id: u32, caller_pid: u32) -> Result<(), StoreError> {
        let entry = self.entries.get_mut(&id).ok_or(StoreError::NotFound)?;
        if entry.owner_pid != caller_pid {
            return Err(StoreError::AccessDenied);
        }
        entry.locked = true;
        Ok(())
    }

    pub fn unlock(&mut self, id: u32, caller_pid: u32) -> Result<(), StoreError> {
        let entry = self.entries.get_mut(&id).ok_or(StoreError::NotFound)?;
        if entry.owner_pid != caller_pid {
            return Err(StoreError::AccessDenied);
        }
        entry.locked = false;
        Ok(())
    }

    pub fn metadata(&self, id: u32, caller_pid: u32) -> Result<KeyMetadata, StoreError> {
        let entry = self.entries.get(&id).ok_or(StoreError::NotFound)?;
        if entry.owner_pid != caller_pid {
            return Err(StoreError::AccessDenied);
        }
        Ok(KeyMetadata {
            id,
            key_type: entry.key_type,
            size: entry.data.len() as u16,
            owner_pid: entry.owner_pid,
            created_at: entry.created_at,
            expires_at: entry.expires_at,
            use_count: entry.use_count,
            locked: entry.locked,
        })
    }

    pub fn count_owned_by(&self, caller_pid: u32) -> u32 {
        self.entries.values().filter(|e| e.owner_pid == caller_pid).count() as u32
    }
}
