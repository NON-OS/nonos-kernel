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

use core::mem;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};
use x86_64::{PhysAddr, VirtAddr};
use crate::memory::frame_alloc;
use crate::memory::layout;
use crate::memory::virt;
use super::constants::*;
use super::error::{HeapError, HeapResult};
use super::types::*;
#[cfg(not(test))]
#[global_allocator]
static KERNEL_HEAP: SecureHeapAllocator = SecureHeapAllocator::new();
pub static HEAP_ZERO_ON_ALLOC: AtomicBool = AtomicBool::new(true);
pub static HEAP_ZERO_ON_FREE: AtomicBool = AtomicBool::new(true);
pub static HEAP_STATS: HeapStatistics = HeapStatistics::new();
static USING_BOOTSTRAP: AtomicBool = AtomicBool::new(true);
// SAFETY: Static memory region, only written during init before other accesses
static mut BOOTSTRAP_HEAP_MEMORY: BootstrapHeapMemory = BootstrapHeapMemory { data: [0u8; BOOTSTRAP_HEAP_SIZE] };
pub fn get_timestamp() -> u64 {
    // SAFETY: RDTSC has no side effects
    unsafe { core::arch::x86_64::_rdtsc() }
}

#[cfg(not(test))]
pub fn init_bootstrap() {
    if !KERNEL_HEAP.is_initialized() {
        // SAFETY: BOOTSTRAP_HEAP_MEMORY is static with proper alignment, unused before this call
        let heap_start = unsafe { BOOTSTRAP_HEAP_MEMORY.data.as_mut_ptr() };
        unsafe { KERNEL_HEAP.init(heap_start, BOOTSTRAP_HEAP_SIZE); }
        HEAP_STATS.set_total_size(BOOTSTRAP_HEAP_SIZE);
        USING_BOOTSTRAP.store(true, Ordering::Release);
    }
}

#[cfg(test)]
pub fn init_bootstrap() {}
#[inline]
pub fn is_using_bootstrap() -> bool {
    USING_BOOTSTRAP.load(Ordering::Acquire)
}

#[cfg(not(test))]
pub fn init() -> HeapResult<()> {
    if KERNEL_HEAP.is_initialized() { return Ok(()); }
    let heap_size = layout::KHEAP_SIZE as usize;
    let heap_pages = (heap_size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE;
    let heap_frames = allocate_heap_frames(heap_pages)?;
    let heap_start = map_heap_memory(&heap_frames)?;

    // SAFETY: heap_start points to freshly mapped memory of heap_size bytes
    unsafe { KERNEL_HEAP.init(heap_start, heap_size); }
    HEAP_STATS.set_total_size(heap_size);
    USING_BOOTSTRAP.store(false, Ordering::Release);
    Ok(())
}

#[cfg(test)]
pub fn init() -> HeapResult<()> { Ok(()) }
fn allocate_heap_frames(page_count: usize) -> HeapResult<alloc::vec::Vec<PhysAddr>> {
    let mut frames = alloc::vec::Vec::with_capacity(page_count);
    for _ in 0..page_count {
        match frame_alloc::allocate_frame() {
            Some(addr) => frames.push(addr),
            None => return Err(HeapError::FrameAllocationFailed),
        }
    }
    Ok(frames)
}

fn map_heap_memory(frames: &[PhysAddr]) -> HeapResult<*mut u8> {
    let heap_start = VirtAddr::new(layout::KHEAP_BASE);
    for (i, &frame_addr) in frames.iter().enumerate() {
        let virt_addr = VirtAddr::new(heap_start.as_u64() + (i * layout::PAGE_SIZE) as u64);
        virt::map_page_4k(virt_addr, frame_addr, true, false, false).map_err(|_| HeapError::MappingFailed)?;
    }
    Ok(heap_start.as_mut_ptr())
}

pub fn set_heap_zero_on_alloc(enable: bool) {
    HEAP_ZERO_ON_ALLOC.store(enable, Ordering::SeqCst);
}

pub fn set_heap_zero_on_free(enable: bool) {
    HEAP_ZERO_ON_FREE.store(enable, Ordering::SeqCst);
}

pub fn get_heap_stats() -> HeapStats {
    HEAP_STATS.get_stats()
}

#[cfg(not(test))]
pub fn get_allocator() -> &'static SecureHeapAllocator {
    &KERNEL_HEAP
}

#[cfg(not(test))]
pub fn verify_heap_integrity() -> bool {
    if !KERNEL_HEAP.is_initialized() { return false; }
    let heap_size = KERNEL_HEAP.get_heap_size();
    if heap_size == 0 { return false; }
    let allocated_ptrs = KERNEL_HEAP.allocated_ptrs.lock();
    for &ptr_addr in allocated_ptrs.iter() {
        if ptr_addr < layout::KHEAP_BASE as usize || ptr_addr >= (layout::KHEAP_BASE + layout::KHEAP_SIZE) as usize {
            return false;
        }

        // SAFETY: Pointer is within heap bounds and tracked by our allocator
        unsafe {
            let header_size = mem::size_of::<AllocationHeader>();
            let header_ptr = (ptr_addr - header_size) as *const AllocationHeader;
            let header = ptr::read_volatile(header_ptr);
            if !header.is_valid() { return false; }
            let canary_ptr = (ptr_addr + header.canary_offset) as *const u64;
            let canary = ptr::read_volatile(canary_ptr);
            if canary != KERNEL_HEAP.canary_value { return false; }
            let current_time = get_timestamp();
            if current_time < header.allocated_at { return false; }
        }
    }
    true
}

#[cfg(test)]
pub fn verify_heap_integrity() -> bool { true }
