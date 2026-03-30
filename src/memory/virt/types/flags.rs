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

use super::super::constants::*;

#[repr(u64)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum VmFlags {
    None = 0,
    Present = PTE_PRESENT,
    Write = PTE_WRITABLE,
    User = PTE_USER,
    WriteThrough = PTE_WRITE_THROUGH,
    CacheDisable = PTE_CACHE_DISABLE,
    Global = PTE_GLOBAL,
    NoExecute = PTE_NO_EXECUTE,
}

impl VmFlags {
    pub const READ: VmFlags = VmFlags::Present;
    pub const RW: VmFlags = VmFlags::Write;
    pub const READ_WRITE: VmFlags = VmFlags::Present;
    pub const NX: VmFlags = VmFlags::NoExecute;
    pub const PWT: VmFlags = VmFlags::WriteThrough;
    pub const PCD: VmFlags = VmFlags::CacheDisable;
    pub const GLOBAL: VmFlags = VmFlags::Global;
    pub const USER: VmFlags = VmFlags::User;

    #[inline]
    pub const fn contains(self, other: VmFlags) -> bool {
        (self as u64) & (other as u64) != 0
    }

    #[inline]
    pub const fn bits(self) -> u64 {
        self as u64
    }
}
