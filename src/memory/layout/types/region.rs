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

use super::super::constants::PAGE_SIZE_U64;
use super::region_kind::RegionKind;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub start: u64,
    pub end: u64,
    pub kind: RegionKind,
}

impl Region {
    pub const fn new(start: u64, end: u64, kind: RegionKind) -> Self {
        Self { start, end, kind }
    }

    #[inline]
    pub const fn len(&self) -> u64 {
        if self.end > self.start {
            self.end - self.start
        } else {
            0
        }
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    #[inline]
    pub const fn is_usable(&self) -> bool {
        self.kind.is_usable()
    }

    #[inline]
    pub const fn start_addr(&self) -> u64 {
        self.start
    }

    #[inline]
    pub const fn end_addr(&self) -> u64 {
        self.end
    }

    #[inline]
    pub const fn page_count(&self) -> u64 {
        self.len() / PAGE_SIZE_U64
    }

    #[inline]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}
