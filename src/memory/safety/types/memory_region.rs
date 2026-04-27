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

use super::protection_level::ProtectionLevel;

#[derive(Debug, Clone)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub name: &'static str,
    pub protection: ProtectionLevel,
    pub read_allowed: bool,
    pub write_allowed: bool,
    pub execute_allowed: bool,
    pub user_accessible: bool,
}

impl MemoryRegion {
    pub const fn new(
        start: u64,
        end: u64,
        name: &'static str,
        protection: ProtectionLevel,
        read: bool,
        write: bool,
        execute: bool,
        user: bool,
    ) -> Self {
        Self {
            start,
            end,
            name,
            protection,
            read_allowed: read,
            write_allowed: write,
            execute_allowed: execute,
            user_accessible: user,
        }
    }

    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    pub const fn contains_range(&self, addr: u64, size: u64) -> bool {
        let end_addr = addr.saturating_add(size);
        addr >= self.start && end_addr <= self.end
    }
}
