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

use core::alloc::{GlobalAlloc, Layout};
use core::mem;
use core::ptr::{self, null_mut};
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use alloc::collections::BTreeSet;
use linked_list_allocator::LockedHeap;
use spin::Mutex;
use super::constants::*;
#[repr(C, align(4096))]
pub struct BootstrapHeapMemory {
    pub data: [u8; BOOTSTRAP_HEAP_SIZE],
}
#[repr(C)]
#[derive(Clone, Copy)]
pub struct AllocationHeader {
    pub magic: u32,
    pub size: usize,
    pub canary_offset: usize,
    pub allocated_at: u64,
}

impl AllocationHeader {
    pub const fn new(size: usize, timestamp: u64) -> Self {
        Self { magic: ALLOCATION_MAGIC, size, canary_offset: size, allocated_at: timestamp }
    }

    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.magic == ALLOCATION_MAGIC
    }
}

pub struct HeapStatistics {
    pub total_size: AtomicUsize,
    pub current_usage: AtomicUsize,
    pub peak_usage: AtomicUsize,
    pub allocation_count: AtomicUsize,
    pub deallocation_count: AtomicUsize,
}

impl HeapStatistics {
    pub const fn new() -> Self {
        Self {
            total_size: AtomicUsize::new(0),
            current_usage: AtomicUsize::new(0),
            peak_usage: AtomicUsize::new(0),
            allocation_count: AtomicUsize::new(0),
            deallocation_count: AtomicUsize::new(0),
        }
    }

    pub fn record_allocation(&self, size: usize) {
        self.allocation_count.fetch_add(1, Ordering::Relaxed);
        let new_usage = self.current_usage.fetch_add(size, Ordering::AcqRel) + size;
        loop {
            let current_peak = self.peak_usage.load(Ordering::Relaxed);
            if new_usage <= current_peak { break; }
            if self.peak_usage.compare_exchange_weak(current_peak, new_usage, Ordering::AcqRel, Ordering::Relaxed).is_ok() { break; }
        }
    }

    pub fn record_deallocation(&self, size: usize) {
        self.deallocation_count.fetch_add(1, Ordering::Relaxed);
        self.current_usage.fetch_sub(size, Ordering::AcqRel);
    }

    pub fn set_total_size(&self, size: usize) {
        self.total_size.store(size, Ordering::Release);
    }

    pub fn get_stats(&self) -> HeapStats {
        HeapStats {
            total_size: self.total_size.load(Ordering::Acquire),
            current_usage: self.current_usage.load(Ordering::Acquire),
            peak_usage: self.peak_usage.load(Ordering::Acquire),
            allocation_count: self.allocation_count.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct HeapStats {
    pub total_size: usize,
    pub current_usage: usize,
    pub peak_usage: usize,
    pub allocation_count: usize,
}

impl HeapStats {
    #[inline]
    pub const fn free_memory(&self) -> usize {
        if self.total_size > self.current_usage { self.total_size - self.current_usage } else { 0 }
    }

    #[inline]
    pub fn usage_percent(&self) -> f64 {
        if self.total_size == 0 { 0.0 } else { (self.current_usage as f64 / self.total_size as f64) * 100.0 }
    }
}

pub struct SecureHeapAllocator {
    pub inner: LockedHeap,
    pub allocated_ptrs: Mutex<BTreeSet<usize>>,
    pub canary_value: u64,
    pub initialized: AtomicBool,
    pub heap_size: AtomicUsize,
}

impl SecureHeapAllocator {
    pub const fn new() -> Self {
        Self {
            inner: LockedHeap::empty(),
            allocated_ptrs: Mutex::new(BTreeSet::new()),
            canary_value: CANARY_VALUE,
            initialized: AtomicBool::new(false),
            heap_size: AtomicUsize::new(0),
        }
    }

    #[inline]
    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::Acquire)
    }

    /// # Safety
    /// - `heap_start` must point to valid, unused memory of at least `heap_size` bytes
    /// - Memory must remain valid for the lifetime of the allocator
    pub unsafe fn init(&self, heap_start: *mut u8, heap_size: usize) {
        self.inner.lock().init(heap_start, heap_size);
        self.heap_size.store(heap_size, Ordering::Release);
        self.initialized.store(true, Ordering::Release);
    }

    #[inline]
    pub fn get_heap_size(&self) -> usize {
        self.heap_size.load(Ordering::Acquire)
    }
}

unsafe impl GlobalAlloc for SecureHeapAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        if !self.is_initialized() { return null_mut(); }
        let header_size = mem::size_of::<AllocationHeader>();
        let total_size = match header_size.checked_add(layout.size()).and_then(|s| s.checked_add(mem::size_of::<u64>())) {
            Some(size) => size,
            None => return null_mut(),
        };

        let align = layout.align().max(MIN_ALIGNMENT);
        let adjusted_layout = match Layout::from_size_align(total_size, align) {
            Ok(l) => l,
            Err(_) => return null_mut(),
        };

        let raw_ptr = self.inner.alloc(adjusted_layout);
        if raw_ptr.is_null() { return null_mut(); }
        let header_ptr = raw_ptr as *mut AllocationHeader;
        let data_ptr = raw_ptr.add(header_size);
        let canary_ptr = data_ptr.add(layout.size()) as *mut u64;
        // SAFETY: raw_ptr is valid and we have exclusive access
        let header = AllocationHeader::new(layout.size(), super::manager::get_timestamp());
        ptr::write_volatile(header_ptr, header);
        // SAFETY: canary_ptr is within our allocated region
        ptr::write_volatile(canary_ptr, self.canary_value);
        let data_addr = data_ptr as usize;
        {
            let mut allocated = self.allocated_ptrs.lock();
            if allocated.contains(&data_addr) {
                self.inner.dealloc(raw_ptr, adjusted_layout);
                return null_mut();
            }
            allocated.insert(data_addr);
        }

        super::manager::HEAP_STATS.record_allocation(layout.size());
        if super::manager::HEAP_ZERO_ON_ALLOC.load(Ordering::Relaxed) {
            // SAFETY: data_ptr is valid and we have exclusive access
            ptr::write_bytes(data_ptr, 0, layout.size());
        }

        data_ptr
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ptr.is_null() || !self.is_initialized() { return; }
        let ptr_addr = ptr as usize;
        let was_allocated = { self.allocated_ptrs.lock().remove(&ptr_addr) };
        if !was_allocated { return; }
        let header_size = mem::size_of::<AllocationHeader>();
        let raw_ptr = ptr.sub(header_size);
        let header_ptr = raw_ptr as *const AllocationHeader;
        // SAFETY: We verified this pointer was allocated by us
        let header = ptr::read_volatile(header_ptr);
        if !header.is_valid() || header.size != layout.size() { return; }
        let canary_ptr = ptr.add(header.canary_offset) as *const u64;
        // SAFETY: canary_ptr is within our allocated region
        let canary = ptr::read_volatile(canary_ptr);
        if canary != self.canary_value { return; }
        if super::manager::HEAP_ZERO_ON_FREE.load(Ordering::Relaxed) {
            // SAFETY: ptr is valid and we're about to free it
            ptr::write_bytes(ptr, 0, layout.size());
        }

        let total_size = header_size + layout.size() + mem::size_of::<u64>();
        let align = layout.align().max(MIN_ALIGNMENT);
        if let Ok(adjusted_layout) = Layout::from_size_align(total_size, align) {
            super::manager::HEAP_STATS.record_deallocation(layout.size());
            // SAFETY: raw_ptr was allocated with this layout
            self.inner.dealloc(raw_ptr, adjusted_layout);
        }
    }
}
