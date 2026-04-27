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

use alloc::collections::BTreeMap;

struct FdEntry {
    service_handle: u64,
}

struct ProcessFdTable {
    entries: BTreeMap<i32, FdEntry>,
    next_fd: i32,
}

impl ProcessFdTable {
    const fn new() -> Self {
        Self { entries: BTreeMap::new(), next_fd: 3 }
    }

    fn allocate(&mut self, service_handle: u64) -> i32 {
        let fd = self.next_fd;
        self.next_fd += 1;
        self.entries.insert(fd, FdEntry { service_handle });
        fd
    }

    fn get(&self, fd: i32) -> Option<&FdEntry> {
        self.entries.get(&fd)
    }
    fn remove(&mut self, fd: i32) -> Option<FdEntry> {
        self.entries.remove(&fd)
    }
}

static GLOBAL_FD_TABLES: spin::RwLock<BTreeMap<u32, ProcessFdTable>> =
    spin::RwLock::new(BTreeMap::new());

pub(super) fn allocate_fd(pid: u32, service_handle: u64, _flags: i32) -> i32 {
    let mut tables = GLOBAL_FD_TABLES.write();
    let table = tables.entry(pid).or_insert_with(ProcessFdTable::new);
    table.allocate(service_handle)
}

pub(super) fn lookup_fd(pid: u32, fd: i32) -> Option<u64> {
    let tables = GLOBAL_FD_TABLES.read();
    tables.get(&pid).and_then(|t| t.get(fd).map(|e| e.service_handle))
}

pub(super) fn close_fd(pid: u32, fd: i32) -> bool {
    let mut tables = GLOBAL_FD_TABLES.write();
    if let Some(table) = tables.get_mut(&pid) {
        table.remove(fd).is_some()
    } else {
        false
    }
}
