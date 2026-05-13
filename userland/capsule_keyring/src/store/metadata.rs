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

use super::types::{KeyMetadata, Store, StoreError};

impl Store {
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
}
