// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtectionLevel {
    None,
    Basic,
    Paranoid,
    Cryptographic,
}

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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    Read,
    Write,
    Execute,
}

#[derive(Debug, Clone, Copy)]
pub struct AccessPattern {
    pub addr: u64,
    pub size: usize,
    pub timestamp: u64,
    pub access_type: AccessType,
}

#[derive(Debug)]
pub enum MemoryAnomaly {
    BufferOverflow {
        start_addr: u64,
        pattern_length: usize,
    },

    UseAfterFree {
        addr: u64,
        confidence: f32,
    },
}

#[derive(Debug, Clone)]
pub struct GuardRegion {
    pub start: u64,
    pub end: u64,
    pub region_type: GuardType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardType {
    StackGuard,
    HeapGuard,
    RedZone,
    Canary,
}

#[derive(Debug)]
pub struct MemoryStats {
    pub violations: usize,
    pub protection_level: ProtectionLevel,
    pub regions_count: usize,
    pub access_patterns: usize,
}
