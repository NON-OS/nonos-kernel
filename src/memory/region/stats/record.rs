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

use super::state::RegionStatistics;
use core::sync::atomic::Ordering;

impl RegionStatistics {
    pub fn record_allocation(&self, size: u64) {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_add(size, Ordering::Relaxed);
    }

    pub fn record_deallocation(&self, size: u64) {
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.allocated_bytes.fetch_sub(size, Ordering::Relaxed);
        self.free_bytes.fetch_add(size, Ordering::Relaxed);
    }

    pub fn record_merge(&self) {
        self.merge_count.fetch_add(1, Ordering::Relaxed);
    }
    pub fn record_split(&self) {
        self.split_count.fetch_add(1, Ordering::Relaxed);
    }

    pub fn add_region(&self, size: u64, is_free: bool) {
        self.total_regions.fetch_add(1, Ordering::Relaxed);
        if is_free {
            self.free_bytes.fetch_add(size, Ordering::Relaxed);
        } else {
            self.allocated_bytes.fetch_add(size, Ordering::Relaxed);
        }
    }

    pub fn remove_region(&self, size: u64, is_free: bool) {
        self.total_regions.fetch_sub(1, Ordering::Relaxed);
        if is_free {
            self.free_bytes.fetch_sub(size, Ordering::Relaxed);
        } else {
            self.allocated_bytes.fetch_sub(size, Ordering::Relaxed);
        }
    }

    pub fn record_fragmentation(&self) {
        self.fragmentation_count.fetch_add(1, Ordering::Relaxed);
    }
    pub fn reduce_fragmentation(&self) {
        self.fragmentation_count.fetch_sub(1, Ordering::Relaxed);
    }
}
