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

use crate::memory::paging::constants::*;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct PagePermissions {
    bits: u32,
}

impl PagePermissions {
    pub const READ: Self = Self { bits: PERM_READ };
    pub const WRITE: Self = Self { bits: PERM_WRITE };
    pub const EXECUTE: Self = Self { bits: PERM_EXECUTE };
    pub const USER: Self = Self { bits: PERM_USER };
    pub const GLOBAL: Self = Self { bits: PERM_GLOBAL };
    pub const NO_CACHE: Self = Self { bits: PERM_NO_CACHE };
    pub const WRITE_THROUGH: Self = Self { bits: PERM_WRITE_THROUGH };
    pub const COW: Self = Self { bits: PERM_COW };
    pub const DEMAND: Self = Self { bits: PERM_DEMAND };
    pub const ZERO_FILL: Self = Self { bits: PERM_ZERO_FILL };
    pub const SHARED: Self = Self { bits: PERM_SHARED };
    pub const LOCKED: Self = Self { bits: PERM_LOCKED };
    pub const DEVICE: Self = Self { bits: PERM_DEVICE };

    pub const fn empty() -> Self { Self { bits: 0 } }
    pub const fn from_bits(bits: u32) -> Self { Self { bits } }
    pub const fn bits(&self) -> u32 { self.bits }
    pub const fn contains(self, other: Self) -> bool { (self.bits & other.bits) == other.bits }
    pub const fn union(self, other: Self) -> Self { Self { bits: self.bits | other.bits } }
    pub const fn remove(self, other: Self) -> Self { Self { bits: self.bits & !other.bits } }
    pub const fn insert(self, other: Self) -> Self { self.union(other) }
    pub const fn is_wx_violation(&self) -> bool { self.contains(Self::WRITE) && self.contains(Self::EXECUTE) }

    pub const fn to_pte_flags(&self) -> u64 {
        let mut flags = PTE_PRESENT;
        if self.contains(Self::WRITE) { flags |= PTE_WRITABLE; }
        if self.contains(Self::USER) { flags |= PTE_USER; }
        if self.contains(Self::WRITE_THROUGH) { flags |= PTE_WRITE_THROUGH; }
        if self.contains(Self::NO_CACHE) { flags |= PTE_CACHE_DISABLE; }
        if self.contains(Self::GLOBAL) { flags |= PTE_GLOBAL; }
        if !self.contains(Self::EXECUTE) { flags |= PTE_NO_EXECUTE; }
        flags
    }

    pub const fn kernel_ro() -> Self { Self { bits: PERM_READ } }
    pub const fn kernel_rw() -> Self { Self { bits: PERM_READ | PERM_WRITE } }
    pub const fn kernel_rx() -> Self { Self { bits: PERM_READ | PERM_EXECUTE } }
    pub const fn user_ro() -> Self { Self { bits: PERM_READ | PERM_USER } }
    pub const fn user_rw() -> Self { Self { bits: PERM_READ | PERM_WRITE | PERM_USER } }
    pub const fn user_rx() -> Self { Self { bits: PERM_READ | PERM_EXECUTE | PERM_USER } }
    pub const fn device() -> Self { Self { bits: PERM_READ | PERM_WRITE | PERM_NO_CACHE | PERM_DEVICE } }
}

impl core::ops::BitOr for PagePermissions {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self { self.union(rhs) }
}

impl core::ops::BitOrAssign for PagePermissions {
    fn bitor_assign(&mut self, rhs: Self) { *self = self.union(rhs); }
}

impl core::ops::BitAnd for PagePermissions {
    type Output = Self;
    fn bitand(self, rhs: Self) -> Self { Self { bits: self.bits & rhs.bits } }
}
