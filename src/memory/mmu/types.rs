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

use super::constants::*;
// ============================================================================
// PROTECTION FLAGS
// ============================================================================
#[derive(Debug, Clone, Copy, Default)]
pub struct ProtectionFlags {
    pub smep_enabled: bool,
    pub smap_enabled: bool,
    pub nx_enabled: bool,
    pub wp_enabled: bool,
}

impl ProtectionFlags {
    pub const fn new() -> Self {
        Self {
            smep_enabled: false,
            smap_enabled: false,
            nx_enabled: false,
            wp_enabled: true,
        }
    }

    pub const fn is_fully_protected(&self) -> bool {
        self.smep_enabled && self.smap_enabled && self.nx_enabled && self.wp_enabled
    }
}
// ============================================================================
// PAGE TABLE ENTRY
// ============================================================================
#[derive(Debug, Clone, Copy, Default)]
pub struct PageTableEntry {
    pub present: bool,
    pub writable: bool,
    pub user_accessible: bool,
    pub write_through: bool,
    pub cache_disabled: bool,
    pub accessed: bool,
    pub dirty: bool,
    pub huge_page: bool,
    pub global: bool,
    pub no_execute: bool,
    pub physical_address: u64,
}

impl PageTableEntry {
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
    pub const fn is_wx_violation(&self) -> bool {
        self.writable && !self.no_execute
    }
}

// ============================================================================
// PAGE PERMISSIONS
// ============================================================================
#[derive(Debug, Clone, Copy, Default)]
pub struct PagePermissions {
    pub writable: bool,
    pub user_accessible: bool,
    pub executable: bool,
    pub cache_disabled: bool,
}

impl PagePermissions {
    pub const fn kernel_ro() -> Self {
        Self {
            writable: false,
            user_accessible: false,
            executable: false,
            cache_disabled: false,
        }
    }

    pub const fn kernel_rw() -> Self {
        Self {
            writable: true,
            user_accessible: false,
            executable: false,
            cache_disabled: false,
        }
    }

    pub const fn kernel_rx() -> Self {
        Self {
            writable: false,
            user_accessible: false,
            executable: true,
            cache_disabled: false,
        }
    }

    pub const fn device() -> Self {
        Self {
            writable: true,
            user_accessible: false,
            executable: false,
            cache_disabled: true,
        }
    }

    pub const fn is_wx_violation(&self) -> bool {
        self.writable && self.executable
    }

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
