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

//! Virtual Memory Statistics (Lock-Free)

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

use super::types::VmType;

/// Lock-free virtual memory statistics.
pub struct VirtualMemoryStatistics {
    /// Total number of VM areas.
    pub(crate) total_vm_areas: AtomicUsize,
    /// Total virtual memory mapped.
    pub(crate) total_virtual_memory: AtomicU64,
    /// Heap memory usage.
    pub(crate) heap_usage: AtomicU64,
    /// Stack memory usage.
    pub(crate) stack_usage: AtomicU64,
    /// Mmap memory usage.
    pub(crate) mmap_usage: AtomicU64,
    /// Page fault count.
    pub(crate) page_faults: AtomicU64,
    /// Protection fault count.
    pub(crate) protection_faults: AtomicU64,
    /// Swap operation count.
    pub(crate) swap_operations: AtomicU64,
    /// TLB shootdown count.
    pub(crate) tlb_shootdowns: AtomicU64,
}

impl VirtualMemoryStatistics {
    /// Creates new statistics (all zeros).
    pub const fn new() -> Self {
        Self {
            total_vm_areas: AtomicUsize::new(0),
            total_virtual_memory: AtomicU64::new(0),
            heap_usage: AtomicU64::new(0),
            stack_usage: AtomicU64::new(0),
            mmap_usage: AtomicU64::new(0),
            page_faults: AtomicU64::new(0),
            protection_faults: AtomicU64::new(0),
            swap_operations: AtomicU64::new(0),
            tlb_shootdowns: AtomicU64::new(0),
        }
    }

    /// Records a new VM area.
    pub fn record_vm_area(&self, size: u64, vm_type: VmType) {
        self.total_vm_areas.fetch_add(1, Ordering::Relaxed);
        self.total_virtual_memory.fetch_add(size, Ordering::Relaxed);

        match vm_type {
            VmType::Heap => {
                self.heap_usage.fetch_add(size, Ordering::Relaxed);
            }
            VmType::Stack => {
                self.stack_usage.fetch_add(size, Ordering::Relaxed);
            }
            VmType::Anonymous | VmType::File | VmType::Shared => {
                self.mmap_usage.fetch_add(size, Ordering::Relaxed);
            }
            _ => {}
        };
    }

    /// Records VM area removal.
    pub fn record_vm_area_removal(&self, size: u64, vm_type: VmType) {
        self.total_vm_areas.fetch_sub(1, Ordering::Relaxed);
        self.total_virtual_memory.fetch_sub(size, Ordering::Relaxed);

        match vm_type {
            VmType::Heap => {
                self.heap_usage.fetch_sub(size, Ordering::Relaxed);
            }
            VmType::Stack => {
                self.stack_usage.fetch_sub(size, Ordering::Relaxed);
            }
            VmType::Anonymous | VmType::File | VmType::Shared => {
                self.mmap_usage.fetch_sub(size, Ordering::Relaxed);
            }
            _ => {}
        };
    }

    /// Records a page fault.
    pub fn record_page_fault(&self) {
        self.page_faults.fetch_add(1, Ordering::Relaxed);
    }

    /// Records a protection fault.
    pub fn record_protection_fault(&self) {
        self.protection_faults.fetch_add(1, Ordering::Relaxed);
    }

    /// Records TLB shootdowns.
    pub fn record_tlb_shootdowns(&self, count: u64) {
        self.tlb_shootdowns.fetch_add(count, Ordering::Relaxed);
    }

    /// Returns total VM areas.
    pub fn total_vm_areas(&self) -> usize {
        self.total_vm_areas.load(Ordering::Relaxed)
    }

    /// Returns total virtual memory.
    pub fn total_virtual_memory(&self) -> u64 {
        self.total_virtual_memory.load(Ordering::Relaxed)
    }

    /// Returns heap usage.
    pub fn heap_usage(&self) -> u64 {
        self.heap_usage.load(Ordering::Relaxed)
    }

    /// Returns stack usage.
    pub fn stack_usage(&self) -> u64 {
        self.stack_usage.load(Ordering::Relaxed)
    }

    /// Returns mmap usage.
    pub fn mmap_usage(&self) -> u64 {
        self.mmap_usage.load(Ordering::Relaxed)
    }

    /// Returns page fault count.
    pub fn page_faults(&self) -> u64 {
        self.page_faults.load(Ordering::Relaxed)
    }

    /// Returns protection fault count.
    pub fn protection_faults(&self) -> u64 {
        self.protection_faults.load(Ordering::Relaxed)
    }

    /// Returns swap operation count.
    pub fn swap_operations(&self) -> u64 {
        self.swap_operations.load(Ordering::Relaxed)
    }

    /// Returns TLB shootdown count.
    pub fn tlb_shootdowns(&self) -> u64 {
        self.tlb_shootdowns.load(Ordering::Relaxed)
    }
}

impl Default for VirtualMemoryStatistics {
    fn default() -> Self {
        Self::new()
    }
}
