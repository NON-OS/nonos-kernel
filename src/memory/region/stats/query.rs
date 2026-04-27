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
    pub fn total_regions(&self) -> usize {
        self.total_regions.load(Ordering::Relaxed)
    }
    pub fn allocated_bytes(&self) -> u64 {
        self.allocated_bytes.load(Ordering::Relaxed)
    }
    pub fn free_bytes(&self) -> u64 {
        self.free_bytes.load(Ordering::Relaxed)
    }
    pub fn allocation_count(&self) -> u64 {
        self.allocation_count.load(Ordering::Relaxed)
    }
    pub fn deallocation_count(&self) -> u64 {
        self.deallocation_count.load(Ordering::Relaxed)
    }
    pub fn merge_count(&self) -> u64 {
        self.merge_count.load(Ordering::Relaxed)
    }
    pub fn split_count(&self) -> u64 {
        self.split_count.load(Ordering::Relaxed)
    }
    pub fn fragmentation_count(&self) -> usize {
        self.fragmentation_count.load(Ordering::Relaxed)
    }
}
