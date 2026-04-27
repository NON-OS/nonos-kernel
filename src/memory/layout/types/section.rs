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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Section {
    pub start: u64,
    pub end: u64,
    pub rx: bool,
    pub rw: bool,
    pub nx: bool,
    pub global: bool,
}

impl Section {
    pub const fn new(start: u64, end: u64, rx: bool, rw: bool, nx: bool, global: bool) -> Self {
        Self { start, end, rx, rw, nx, global }
    }

    #[inline]
    pub const fn size(&self) -> u64 {
        if self.end > self.start {
            self.end - self.start
        } else {
            0
        }
    }

    #[inline]
    pub const fn page_count(&self) -> u64 {
        (self.size() + PAGE_SIZE_U64 - 1) / PAGE_SIZE_U64
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.end <= self.start
    }

    #[inline]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.start && addr < self.end
    }
}
