// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use core::sync::atomic::{AtomicUsize, AtomicU64, Ordering};
use x86_64::{PhysAddr, VirtAddr};
#[derive(Debug, Clone, Copy)]
pub struct AllocatedPage {
    pub page_id: u64,
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub allocation_time: u64,
    pub size: usize,
}

pub struct AllocatorStats {
    pub total_allocations: AtomicU64,
    pub total_deallocations: AtomicU64,
    pub active_pages: AtomicUsize,
    pub bytes_allocated: AtomicU64,
    pub peak_pages: AtomicUsize,
}

impl AllocatorStats {
    pub const fn new() -> Self {
        Self {
            total_allocations: AtomicU64::new(0),
            total_deallocations: AtomicU64::new(0),
            active_pages: AtomicUsize::new(0),
            bytes_allocated: AtomicU64::new(0),
            peak_pages: AtomicUsize::new(0),
        }
    }

    pub fn record_allocation(&self, size: usize) {
        self.total_allocations.fetch_add(1, Ordering::Relaxed);
        let new_count = self.active_pages.fetch_add(1, Ordering::Relaxed) + 1;
        self.bytes_allocated.fetch_add(size as u64, Ordering::Relaxed);
        loop {
            let current_peak = self.peak_pages.load(Ordering::Relaxed);
            if new_count <= current_peak { break; }
            if self.peak_pages.compare_exchange_weak(current_peak, new_count, Ordering::Relaxed, Ordering::Relaxed).is_ok() { break; }
        }
    }

    pub fn record_deallocation(&self, size: usize) {
        self.total_deallocations.fetch_add(1, Ordering::Relaxed);
        self.active_pages.fetch_sub(1, Ordering::Relaxed);
        self.bytes_allocated.fetch_sub(size as u64, Ordering::Relaxed);
    }
}

#[derive(Debug, Clone, Copy)]
pub struct PageAllocatorStats {
    pub total_allocations: u64,
    pub total_deallocations: u64,
    pub active_pages: usize,
    pub bytes_allocated: u64,
    pub peak_pages: usize,
    pub allocated_pages: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct PageInfo {
    pub page_id: u64,
    pub virtual_addr: VirtAddr,
    pub physical_addr: PhysAddr,
    pub allocation_time: u64,
    pub size: usize,
}
