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

//! MMU Types

use super::constants::*;

// ============================================================================
// PROTECTION FLAGS
// ============================================================================

/// CPU protection features status.
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtectionFlags {
    /// SMEP (Supervisor Mode Execution Prevention) enabled
    pub smep_enabled: bool,
    /// SMAP (Supervisor Mode Access Prevention) enabled
    pub smap_enabled: bool,
    /// NX (No-Execute) bit enabled
    pub nx_enabled: bool,
    /// WP (Write Protect) bit enabled
    pub wp_enabled: bool,
}

impl ProtectionFlags {
    /// Creates default protection flags.
    pub const fn new() -> Self {
        Self {
            smep_enabled: false,
            smap_enabled: false,
            nx_enabled: false,
            wp_enabled: true,
        }
    }

    /// Returns true if all security features are enabled.
    pub const fn is_fully_protected(&self) -> bool {
        self.smep_enabled && self.smap_enabled && self.nx_enabled && self.wp_enabled
    }
}

// ============================================================================
// PAGE TABLE ENTRY
// ============================================================================

/// Represents a decoded page table entry.
#[derive(Debug, Clone, Copy, Default)]
pub struct PageTableEntry {
    /// Page is present
    pub present: bool,
    /// Page is writable
    pub writable: bool,
    /// Page is user accessible
    pub user_accessible: bool,
    /// Write-through caching
    pub write_through: bool,
    /// Cache disabled
    pub cache_disabled: bool,
    /// Page has been accessed
    pub accessed: bool,
    /// Page has been written (dirty)
    pub dirty: bool,
    /// Huge page (2M/1G)
    pub huge_page: bool,
    /// Global page (not flushed on CR3 switch)
    pub global: bool,
    /// No-execute bit set
    pub no_execute: bool,
    /// Physical address
    pub physical_address: u64,
}

impl PageTableEntry {
    /// Creates an empty (not present) entry.
    pub const fn empty() -> Self {
        Self {
            present: false,
            writable: false,
            user_accessible: false,
            write_through: false,
            cache_disabled: false,
            accessed: false,
            dirty: false,
            huge_page: false,
            global: false,
            no_execute: false,
            physical_address: 0,
        }
    }

    /// Decodes a raw PTE value.
    pub fn from_raw(raw: u64) -> Self {
        Self {
            present: raw & PTE_PRESENT != 0,
            writable: raw & PTE_WRITABLE != 0,
            user_accessible: raw & PTE_USER != 0,
            write_through: raw & PTE_WRITE_THROUGH != 0,
            cache_disabled: raw & PTE_CACHE_DISABLE != 0,
            accessed: raw & PTE_ACCESSED != 0,
            dirty: raw & PTE_DIRTY != 0,
            huge_page: raw & PTE_HUGE_PAGE != 0,
            global: raw & PTE_GLOBAL != 0,
            no_execute: raw & PTE_NO_EXECUTE != 0,
            physical_address: raw & PTE_ADDR_MASK,
        }
    }

    /// Encodes to a raw PTE value.
    pub fn to_raw(&self) -> u64 {
        let mut raw = self.physical_address & PTE_ADDR_MASK;
        if self.present {
            raw |= PTE_PRESENT;
        }
        if self.writable {
            raw |= PTE_WRITABLE;
        }
        if self.user_accessible {
            raw |= PTE_USER;
        }
        if self.write_through {
            raw |= PTE_WRITE_THROUGH;
        }
        if self.cache_disabled {
            raw |= PTE_CACHE_DISABLE;
        }
        if self.accessed {
            raw |= PTE_ACCESSED;
        }
        if self.dirty {
            raw |= PTE_DIRTY;
        }
        if self.huge_page {
            raw |= PTE_HUGE_PAGE;
        }
        if self.global {
            raw |= PTE_GLOBAL;
        }
        if self.no_execute {
            raw |= PTE_NO_EXECUTE;
        }
        raw
    }

    /// Checks if this entry violates W^X.
    pub const fn is_wx_violation(&self) -> bool {
        self.writable && !self.no_execute
    }
}

// ============================================================================
// PAGE PERMISSIONS
// ============================================================================

/// Permissions for mapping a page.
#[derive(Debug, Clone, Copy, Default)]
pub struct PagePermissions {
    /// Page is writable
    pub writable: bool,
    /// Page is user accessible
    pub user_accessible: bool,
    /// Page is executable
    pub executable: bool,
    /// Page has cache disabled
    pub cache_disabled: bool,
}

impl PagePermissions {
    /// Creates read-only kernel permissions.
    pub const fn kernel_ro() -> Self {
        Self {
            writable: false,
            user_accessible: false,
            executable: false,
            cache_disabled: false,
        }
    }

    /// Creates read-write kernel permissions.
    pub const fn kernel_rw() -> Self {
        Self {
            writable: true,
            user_accessible: false,
            executable: false,
            cache_disabled: false,
        }
    }

    /// Creates execute-only kernel permissions.
    pub const fn kernel_rx() -> Self {
        Self {
            writable: false,
            user_accessible: false,
            executable: true,
            cache_disabled: false,
        }
    }

    /// Creates device memory permissions (uncached, no-execute).
    pub const fn device() -> Self {
        Self {
            writable: true,
            user_accessible: false,
            executable: false,
            cache_disabled: true,
        }
    }

    /// Checks if these permissions violate W^X.
    pub const fn is_wx_violation(&self) -> bool {
        self.writable && self.executable
    }

    /// Converts to a PageTableEntry.
    pub fn to_pte(&self, physical_address: u64) -> PageTableEntry {
        PageTableEntry {
            present: true,
            writable: self.writable,
            user_accessible: self.user_accessible,
            write_through: false,
            cache_disabled: self.cache_disabled,
            accessed: false,
            dirty: false,
            huge_page: false,
            global: false,
            no_execute: !self.executable,
            physical_address,
        }
    }
}
