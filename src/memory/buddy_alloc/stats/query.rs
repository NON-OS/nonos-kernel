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

use super::super::types::AllocStats;
use super::types::AllocationStatistics;
use core::sync::atomic::Ordering;

impl AllocationStatistics {
    #[inline]
    pub fn total_allocated(&self) -> u64 {
        self.total_allocated.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn peak_allocated(&self) -> u64 {
        self.peak_allocated.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn allocation_count(&self) -> usize {
        self.allocation_count.load(Ordering::Relaxed)
    }

    #[inline]
    pub fn free_count(&self) -> usize {
        self.free_count.load(Ordering::Relaxed)
    }

    pub fn get_stats(&self, active_ranges: usize) -> AllocStats {
        AllocStats {
            total_allocated: self.total_allocated(),
            peak_allocated: self.peak_allocated(),
            allocation_count: self.allocation_count(),
            free_count: self.free_count(),
            active_ranges,
        }
    }
}
