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

#[derive(Debug, Clone, Copy, Default)]
pub struct AllocStats {
    pub total_allocated: u64,
    pub peak_allocated: u64,
    pub allocation_count: usize,
    pub free_count: usize,
    pub active_ranges: usize,
}

impl AllocStats {
    pub const fn new() -> Self {
        Self {
            total_allocated: 0,
            peak_allocated: 0,
            allocation_count: 0,
            free_count: 0,
            active_ranges: 0,
        }
    }

    pub const fn free_memory(&self, total: u64) -> u64 {
        if total > self.total_allocated {
            total - self.total_allocated
        } else {
            0
        }
    }
}
