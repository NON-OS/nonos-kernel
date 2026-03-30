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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum PageSize {
    Size4K = PAGE_SIZE_4K,
    Size2M = PAGE_SIZE_2M,
    Size1G = PAGE_SIZE_1G,
}

impl PageSize {
    #[inline]
    pub const fn bytes(self) -> usize {
        self as usize
    }

    #[inline]
    pub const fn mask(self) -> u64 {
        (self as u64) - 1
    }

    #[inline]
    pub const fn is_aligned(self, addr: u64) -> bool {
        addr & self.mask() == 0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self::Size4K
    }
}
