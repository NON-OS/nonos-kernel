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

#[repr(C, packed)]
#[derive(Debug, Clone, Copy)]
pub struct SratMemoryAffinity {
    pub entry_type: u8,
    pub length: u8,
    pub proximity_domain: u32,
    pub reserved1: u16,
    pub base_address: u64,
    pub length_bytes: u64,
    pub reserved2: u32,
    pub flags: u32,
    pub reserved3: u64,
}

impl SratMemoryAffinity {
    pub const ENABLED: u32 = 1 << 0;
    pub const HOT_PLUGGABLE: u32 = 1 << 1;
    pub const NON_VOLATILE: u32 = 1 << 2;

    pub fn is_enabled(&self) -> bool {
        self.flags & Self::ENABLED != 0
    }
    pub fn is_hot_pluggable(&self) -> bool {
        self.flags & Self::HOT_PLUGGABLE != 0
    }
    pub fn is_non_volatile(&self) -> bool {
        self.flags & Self::NON_VOLATILE != 0
    }
    pub fn end_address(&self) -> u64 {
        self.base_address.saturating_add(self.length_bytes)
    }
    pub fn contains_address(&self, addr: u64) -> bool {
        addr >= self.base_address && addr < self.end_address()
    }
}
