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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageSize {
    Size4KiB,
    Size2MiB,
    Size1GiB,
}

impl PageSize {
    pub const fn bytes(&self) -> usize {
        match self {
            Self::Size4KiB => PAGE_SIZE_4K,
            Self::Size2MiB => PAGE_SIZE_2M,
            Self::Size1GiB => PAGE_SIZE_1G,
        }
    }

    pub const fn align_mask(&self) -> u64 {
        match self {
            Self::Size4KiB => 0xFFF,
            Self::Size2MiB => 0x1F_FFFF,
            Self::Size1GiB => 0x3FFF_FFFF,
        }
    }

    pub const fn is_aligned(&self, addr: u64) -> bool {
        addr & self.align_mask() == 0
    }
}

impl Default for PageSize {
    fn default() -> Self {
        Self::Size4KiB
    }
}
