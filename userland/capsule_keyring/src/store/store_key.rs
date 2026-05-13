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

use super::types::{KeyEntry, KeyType, Store, StoreError, MAX_KEYS, MAX_KEY_SIZE};

impl Store {
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
}
