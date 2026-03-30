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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PercpuRegion {
    pub base: u64,
    pub size: usize,
    pub cpu_id: u32,
}

impl PercpuRegion {
    pub const fn new(base: u64, size: usize, cpu_id: u32) -> Self {
        Self { base, size, cpu_id }
    }

    #[inline]
    pub const fn end(&self) -> u64 {
        self.base + self.size as u64
    }

    #[inline]
    pub const fn contains(&self, addr: u64) -> bool {
        addr >= self.base && addr < self.end()
    }
}
