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
use alloc::string::String;

pub const MAX_HANDLES: usize = 1024;

pub struct Handle {
    pub path: String,
}

pub struct HandleTable {
    next_id: u64,
    table: BTreeMap<u64, Handle>,
}

impl HandleTable {
    pub const fn new() -> Self {
        Self { next_id: 1, table: BTreeMap::new() }
    }

    pub fn insert(&mut self, path: String) -> Option<u64> {
        if self.table.len() >= MAX_HANDLES {
            return None;
        }
        let id = self.next_id;
        self.next_id = self.next_id.wrapping_add(1);
        self.table.insert(id, Handle { path });
        Some(id)
    }

    pub fn path_of(&self, id: u64) -> Option<&str> {
        self.table.get(&id).map(|h| h.path.as_str())
    }

    pub fn remove(&mut self, id: u64) -> bool {
        self.table.remove(&id).is_some()
    }
}
