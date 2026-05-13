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

use super::types::{Store, StoreError};

impl Store {
    pub fn delete(&mut self, id: u32, caller_pid: u32) -> Result<(), StoreError> {
        let entry = self.entries.get(&id).ok_or(StoreError::NotFound)?;
        if entry.owner_pid != caller_pid {
            return Err(StoreError::AccessDenied);
        }
        let mut removed = match self.entries.remove(&id) {
            Some(entry) => entry,
            None => return Err(StoreError::NotFound),
        };
        for byte in removed.data.iter_mut() {
            *byte = 0;
        }
        Ok(())
    }
}
