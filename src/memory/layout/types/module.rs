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

use super::super::constants::{PERM_EXEC, PERM_READ, PERM_WRITE};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ModuleRegion {
    pub base: u64,
    pub size: usize,
    pub name: &'static str,
    pub permissions: u32,
}

impl ModuleRegion {
    pub const fn new(base: u64, size: usize, name: &'static str, permissions: u32) -> Self {
        Self { base, size, name, permissions }
    }

    #[inline]
    pub const fn is_readable(&self) -> bool {
        (self.permissions & PERM_READ) != 0
    }

    #[inline]
    pub const fn is_writable(&self) -> bool {
        (self.permissions & PERM_WRITE) != 0
    }

    #[inline]
    pub const fn is_executable(&self) -> bool {
        (self.permissions & PERM_EXEC) != 0
    }

    #[inline]
    pub const fn end(&self) -> u64 {
        self.base + self.size as u64
    }
}
