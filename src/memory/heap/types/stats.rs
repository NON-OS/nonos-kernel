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

#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    pub total_size: usize,
    pub current_usage: usize,
    pub peak_usage: usize,
    pub allocation_count: usize,
    pub total_allocated: u64,
    pub total_deallocated: u64,
}

impl HeapStats {
    #[inline]
    pub const fn free_memory(&self) -> usize {
        if self.total_size > self.current_usage {
            self.total_size - self.current_usage
        } else {
            0
        }
    }

    #[inline]
    pub fn usage_percent(&self) -> f64 {
        if self.total_size == 0 {
            0.0
        } else {
            (self.current_usage as f64 / self.total_size as f64) * 100.0
        }
    }
}
