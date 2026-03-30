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
pub struct StackRegion {
    pub base: u64,
    pub size: usize,
    pub guard_size: usize,
    pub cpu_id: Option<u32>,
    pub thread_id: Option<u64>,
}

impl StackRegion {
    pub const fn new(base: u64, size: usize, guard_size: usize) -> Self {
        Self { base, size, guard_size, cpu_id: None, thread_id: None }
    }

    pub const fn per_cpu(base: u64, size: usize, guard_size: usize, cpu_id: u32) -> Self {
        Self { base, size, guard_size, cpu_id: Some(cpu_id), thread_id: None }
    }

    #[inline]
    pub const fn total_size(&self) -> usize {
        self.size + self.guard_size
    }

    #[inline]
    pub const fn stack_top(&self) -> u64 {
        self.base + self.size as u64
    }
}
