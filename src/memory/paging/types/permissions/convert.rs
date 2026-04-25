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

use super::flags::PagePermissions;
use crate::memory::paging::constants::*;

impl PagePermissions {
    pub const fn to_pte_flags(&self) -> u64 {
        let mut flags = PTE_PRESENT;
        if self.contains(Self::WRITE) {
            flags |= PTE_WRITABLE;
        }
        if self.contains(Self::USER) {
            flags |= PTE_USER;
        }
        if self.contains(Self::WRITE_THROUGH) {
            flags |= PTE_WRITE_THROUGH;
        }
        if self.contains(Self::NO_CACHE) {
            flags |= PTE_CACHE_DISABLE;
        }
        if self.contains(Self::GLOBAL) {
            flags |= PTE_GLOBAL;
        }
        if !self.contains(Self::EXECUTE) {
            flags |= PTE_NO_EXECUTE;
        }
        flags
    }

    pub const fn kernel_ro() -> Self {
        Self { bits: PERM_READ }
    }
    pub const fn kernel_rw() -> Self {
        Self { bits: PERM_READ | PERM_WRITE }
    }
    pub const fn kernel_rx() -> Self {
        Self { bits: PERM_READ | PERM_EXECUTE }
    }
    pub const fn user_ro() -> Self {
        Self { bits: PERM_READ | PERM_USER }
    }
    pub const fn user_rw() -> Self {
        Self { bits: PERM_READ | PERM_WRITE | PERM_USER }
    }
    pub const fn user_rx() -> Self {
        Self { bits: PERM_READ | PERM_EXECUTE | PERM_USER }
    }
    pub const fn device() -> Self {
        Self { bits: PERM_READ | PERM_WRITE | PERM_NO_CACHE | PERM_DEVICE }
    }
}
