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

//! Memory Safety Types

/// Memory protection level.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ProtectionLevel {
    /// No protection.
    None,
    /// Basic protection.
    Basic,
    /// Paranoid protection with corruption checks.
    Paranoid,
    /// Cryptographic protection.
    Cryptographic,
}

/// Memory region descriptor.
#[derive(Debug, Clone)]
pub struct MemoryRegion {
    /// Region start address.
    pub start: u64,
    /// Region end address.
    pub end: u64,
    /// Region name for diagnostics.
    pub name: &'static str,
    /// Protection level.
    pub protection: ProtectionLevel,
    /// Read access allowed.
    pub read_allowed: bool,
    /// Write access allowed.
    pub write_allowed: bool,
    /// Execute access allowed.
    pub execute_allowed: bool,
    /// User-mode accessible.
    pub user_accessible: bool,
}

impl MemoryRegion {
    /// Creates a new memory region.
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

    /// Returns the size of the region.
    pub const fn size(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    /// Returns true if address is within this region.
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }

    /// Returns true if address range is fully within this region.
    pub const fn contains_range(&self, addr: u64, size: u64) -> bool {
        let end_addr = addr.saturating_add(size);
        addr >= self.start && end_addr <= self.end
    }
}

/// Type of memory access.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AccessType {
    /// Read access.
    Read,
    /// Write access.
    Write,
    /// Execute access.
    Execute,
}

/// Access pattern record.
#[derive(Debug, Clone, Copy)]
pub struct AccessPattern {
    /// Address accessed.
    pub addr: u64,
    /// Size of access.
    pub size: usize,
    /// Timestamp (TSC).
    pub timestamp: u64,
    /// Type of access.
    pub access_type: AccessType,
}

/// Memory anomaly detection result.
#[derive(Debug)]
pub enum MemoryAnomaly {
    /// Potential buffer overflow detected.
    BufferOverflow {
        /// Start address of the pattern.
        start_addr: u64,
        /// Length of the suspicious pattern.
        pattern_length: usize,
    },
    /// Potential use-after-free detected.
    UseAfterFree {
        /// Address of the suspicious access.
        addr: u64,
        /// Detection confidence (0.0-1.0).
        confidence: f32,
    },
}

/// Guard region for stack/heap protection.
#[derive(Debug, Clone)]
pub struct GuardRegion {
    /// Start address.
    pub start: u64,
    /// End address.
    pub end: u64,
    /// Type of guard.
    pub region_type: GuardType,
}

/// Type of guard region.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GuardType {
    /// Stack guard page.
    StackGuard,
    /// Heap guard page.
    HeapGuard,
    /// Red zone.
    RedZone,
    /// Canary region.
    Canary,
}

/// Memory safety statistics.
#[derive(Debug)]
pub struct MemoryStats {
    /// Number of corruption violations detected.
    pub violations: usize,
    /// Current protection level.
    pub protection_level: ProtectionLevel,
    /// Number of tracked regions.
    pub regions_count: usize,
    /// Number of access patterns tracked.
    pub access_patterns: usize,
}
