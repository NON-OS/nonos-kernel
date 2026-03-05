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

//! Kernel Heap Allocator
//! Simple linked-list free block allocator for dynamic memory allocation
//!
//! This allocator provides malloc/free style allocation for the kernel heap.
//! It uses a first-fit algorithm with coalescing of adjacent free blocks.

use core::alloc::{GlobalAlloc, Layout};
use core::ptr::null_mut;
use core::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use crate::sys::serial;

/// Minimum allocation size (to reduce fragmentation)
const MIN_BLOCK_SIZE: usize = 32;

/// Block header size
const HEADER_SIZE: usize = core::mem::size_of::<BlockHeader>();

/// Maximum heap size we'll use (256 MB - supports 4K wallpaper decoding)
const INITIAL_HEAP_SIZE: usize = 256 * 1024 * 1024;

/// Free block header
/// Stored at the beginning of each free block
#[repr(C)]
struct BlockHeader {
    size: usize,        // Size of this block (including header)
    next: *mut BlockHeader, // Pointer to next free block
    magic: u32,         // Magic number for validation (0xDEADBEEF)
}

const BLOCK_MAGIC: u32 = 0xDEAD_BEEF;
const ALLOC_MAGIC: u32 = 0xCAFE_BABE;

/// Allocated block header (smaller, just tracks size)
#[repr(C)]
struct AllocHeader {
    size: usize,
    magic: u32,
}

const ALLOC_HEADER_SIZE: usize = core::mem::size_of::<AllocHeader>();

/// Static heap allocator
static mut HEAP_START: usize = 0;
static mut HEAP_END: usize = 0;
static mut FREE_LIST: *mut BlockHeader = null_mut();
static HEAP_INIT: AtomicBool = AtomicBool::new(false);

/// Statistics
static TOTAL_ALLOCATED: AtomicUsize = AtomicUsize::new(0);
static TOTAL_FREED: AtomicUsize = AtomicUsize::new(0);
static PEAK_USAGE: AtomicUsize = AtomicUsize::new(0);

/// Spinlock for heap operations
static HEAP_LOCK: AtomicBool = AtomicBool::new(false);

fn lock_heap() {
    while HEAP_LOCK.compare_exchange_weak(false, true, Ordering::Acquire, Ordering::Relaxed).is_err() {
        core::hint::spin_loop();
    }
}

fn unlock_heap() {
    HEAP_LOCK.store(false, Ordering::Release);
}

/// Initialize the kernel heap
pub fn init() {
    if HEAP_INIT.load(Ordering::Relaxed) {
        return;
    }

    serial::println(b"[HEAP] Initializing kernel heap...");

    // For initial boot, use a static memory region instead of PMM
    // The bootloader identity-maps physical memory, so we can use
    // a fixed physical address range for the heap

    // Use physical memory starting at 192MB (after kernel at 64MB + 50MB data + margin)
    // Kernel: 64MB base + ~50MB size = ends at ~114MB
    // Heap: starts at 192MB to avoid overlap
    let heap_phys_start: usize = 0xC00_0000; // 192 MB
    let heap_size = INITIAL_HEAP_SIZE;

    unsafe {
        HEAP_START = heap_phys_start;
        HEAP_END = heap_phys_start + heap_size;

        // Initialize the heap as one big free block
        let initial_block = HEAP_START as *mut BlockHeader;
        (*initial_block).size = heap_size;
        (*initial_block).next = null_mut();
        (*initial_block).magic = BLOCK_MAGIC;

        FREE_LIST = initial_block;
    }

    HEAP_INIT.store(true, Ordering::SeqCst);

    serial::print(b"[HEAP] Heap initialized at 0x");
    serial::print_hex(heap_phys_start as u64);
    serial::print(b" size: ");
    serial::print_dec((heap_size / 1024 / 1024) as u64);
    serial::println(b" MB");
}

/// Allocate memory
pub fn alloc(size: usize, align: usize) -> *mut u8 {
    if !HEAP_INIT.load(Ordering::Relaxed) {
        return null_mut();
    }

    if size == 0 {
        return null_mut();
    }

    // Debug: log large allocations
    if size > 1024 * 1024 {
        serial::print(b"[HEAP] Large alloc: ");
        serial::print_dec(size as u64 / 1024 / 1024);
        serial::println(b" MB");
    }

    lock_heap();

    // Calculate total size needed: header + data aligned
    let data_size = size.max(MIN_BLOCK_SIZE);
    let total_size = ALLOC_HEADER_SIZE + data_size;
    let aligned_size = (total_size + align - 1) & !(align - 1);

    if size > 1024 * 1024 {
        serial::print(b"[HEAP] aligned_size: ");
        serial::print_dec(aligned_size as u64);
        serial::println(b"");
    }

    let result = unsafe { alloc_from_freelist(aligned_size, align) };

    if !result.is_null() {
        let current = TOTAL_ALLOCATED.fetch_add(aligned_size, Ordering::Relaxed) + aligned_size;
        let peak = PEAK_USAGE.load(Ordering::Relaxed);
        if current > peak {
            PEAK_USAGE.store(current, Ordering::Relaxed);
        }
    }

    unlock_heap();
    result
}

/// Internal allocation from free list (must hold lock)
unsafe fn alloc_from_freelist(size: usize, align: usize) -> *mut u8 {
    unsafe {
        let mut prev: *mut BlockHeader = null_mut();
        let mut current = FREE_LIST;
        let mut iterations = 0u32;

        // Debug: show free list state for large allocs
        if size > 1024 * 1024 {
            serial::print(b"[HEAP] FREE_LIST: 0x");
            serial::print_hex(FREE_LIST as u64);
            serial::println(b"");
        }

        while !current.is_null() {
            iterations += 1;

            // Safety check for infinite loops
            if iterations > 10000 {
                serial::println(b"[HEAP] ERROR: Infinite loop in free list!");
                return null_mut();
            }

            // Validate block
            if (*current).magic != BLOCK_MAGIC {
                serial::print(b"[HEAP] ERROR: Corrupted block at 0x");
                serial::print_hex(current as u64);
                serial::print(b" magic=0x");
                serial::print_hex((*current).magic as u64);
                serial::println(b"");
                return null_mut();
            }

            let block_size = (*current).size;

            // Calculate aligned data pointer
            let data_start = (current as usize) + ALLOC_HEADER_SIZE;
            let aligned_data = (data_start + align - 1) & !(align - 1);
            let padding = aligned_data - data_start;
            let needed_size = size + padding;

            if block_size >= needed_size {
                // This block is big enough
                let remaining = block_size - needed_size;

                // Debug for large allocs
                if size > 1024 * 1024 {
                    serial::print(b"[HEAP] Found block size=");
                    serial::print_dec(block_size as u64 / 1024 / 1024);
                    serial::print(b"MB needed=");
                    serial::print_dec(needed_size as u64 / 1024 / 1024);
                    serial::println(b"MB");
                }

                if remaining >= HEADER_SIZE + MIN_BLOCK_SIZE {
                    // Split the block
                    let new_block = ((current as usize) + needed_size) as *mut BlockHeader;
                    (*new_block).size = remaining;
                    (*new_block).next = (*current).next;
                    (*new_block).magic = BLOCK_MAGIC;

                    // Update free list
                    if prev.is_null() {
                        FREE_LIST = new_block;
                    } else {
                        (*prev).next = new_block;
                    }

                    // Setup allocated block header
                    let alloc_hdr = current as *mut AllocHeader;
                    (*alloc_hdr).size = needed_size;
                    (*alloc_hdr).magic = ALLOC_MAGIC;

                    if size > 1024 * 1024 {
                        serial::print(b"[HEAP] Allocated at 0x");
                        serial::print_hex(aligned_data as u64);
                        serial::println(b"");
                    }

                    return aligned_data as *mut u8;
                } else {
                    // Use entire block
                    if prev.is_null() {
                        FREE_LIST = (*current).next;
                    } else {
                        (*prev).next = (*current).next;
                    }

                    // Setup allocated block header
                    let alloc_hdr = current as *mut AllocHeader;
                    (*alloc_hdr).size = block_size;
                    (*alloc_hdr).magic = ALLOC_MAGIC;

                    return aligned_data as *mut u8;
                }
            }

            prev = current;
            current = (*current).next;
        }

        // Out of memory
        null_mut()
    }
}

/// Free allocated memory
pub fn free(ptr: *mut u8) {
    if ptr.is_null() {
        return;
    }

    if !HEAP_INIT.load(Ordering::Relaxed) {
        return;
    }

    lock_heap();

    unsafe {
        // Find the allocation header (it's before the data)
        let hdr_addr = (ptr as usize).saturating_sub(ALLOC_HEADER_SIZE);
        let alloc_hdr = hdr_addr as *mut AllocHeader;

        // Validate
        if (*alloc_hdr).magic != ALLOC_MAGIC {
            serial::println(b"[HEAP] ERROR: Invalid free - bad magic!");
            unlock_heap();
            return;
        }

        let block_size = (*alloc_hdr).size;

        TOTAL_FREED.fetch_add(block_size, Ordering::Relaxed);
        TOTAL_ALLOCATED.fetch_sub(block_size, Ordering::Relaxed);

        // Convert to free block
        let free_block = hdr_addr as *mut BlockHeader;
        (*free_block).size = block_size;
        (*free_block).magic = BLOCK_MAGIC;

        // Insert into free list (sorted by address for coalescing)
        insert_free_block(free_block);

        // Try to coalesce adjacent free blocks
        coalesce_free_blocks();
    }

    unlock_heap();
}

/// Insert a free block into the sorted free list
unsafe fn insert_free_block(block: *mut BlockHeader) {
    unsafe {
        let block_addr = block as usize;

        if FREE_LIST.is_null() || block_addr < FREE_LIST as usize {
            // Insert at head
            (*block).next = FREE_LIST;
            FREE_LIST = block;
            return;
        }

        // Find insertion point
        let mut current = FREE_LIST;
        while !(*current).next.is_null() && ((*current).next as usize) < block_addr {
            current = (*current).next;
        }

        (*block).next = (*current).next;
        (*current).next = block;
    }
}

/// Coalesce adjacent free blocks
unsafe fn coalesce_free_blocks() {
    unsafe {
        let mut current = FREE_LIST;

        while !current.is_null() && !(*current).next.is_null() {
            let next = (*current).next;
            let current_end = (current as usize) + (*current).size;

            // Check if blocks are adjacent
            if current_end == next as usize {
                // Merge blocks
                (*current).size += (*next).size;
                (*current).next = (*next).next;
                // Don't advance - check if we can merge more
            } else {
                current = next;
            }
        }
    }
}

/// Reallocate memory
pub fn realloc(ptr: *mut u8, new_size: usize, align: usize) -> *mut u8 {
    if ptr.is_null() {
        return alloc(new_size, align);
    }

    if new_size == 0 {
        free(ptr);
        return null_mut();
    }

    // Get current size
    let old_size = unsafe {
        let hdr_addr = (ptr as usize).saturating_sub(ALLOC_HEADER_SIZE);
        let alloc_hdr = hdr_addr as *const AllocHeader;
        if (*alloc_hdr).magic != ALLOC_MAGIC {
            return null_mut();
        }
        (*alloc_hdr).size - ALLOC_HEADER_SIZE
    };

    // If shrinking and difference is small, keep current block
    if new_size <= old_size {
        return ptr;
    }

    // Allocate new block
    let new_ptr = alloc(new_size, align);
    if new_ptr.is_null() {
        return null_mut();
    }

    // Copy old data
    unsafe {
        core::ptr::copy_nonoverlapping(ptr, new_ptr, old_size.min(new_size));
    }

    // Free old block
    free(ptr);

    new_ptr
}

/// Get heap statistics
pub fn stats() -> (usize, usize, usize, usize) {
    (
        TOTAL_ALLOCATED.load(Ordering::Relaxed),
        TOTAL_FREED.load(Ordering::Relaxed),
        PEAK_USAGE.load(Ordering::Relaxed),
        free_space(),
    )
}

/// Calculate total free space
fn free_space() -> usize {
    if !HEAP_INIT.load(Ordering::Relaxed) {
        return 0;
    }

    lock_heap();

    let mut total: usize = 0;
    let mut current = unsafe { FREE_LIST };

    while !current.is_null() {
        unsafe {
            if (*current).magic == BLOCK_MAGIC {
                total += (*current).size;
            }
            current = (*current).next;
        }
    }

    unlock_heap();
    total
}

/// Check if heap is initialized
pub fn is_init() -> bool {
    HEAP_INIT.load(Ordering::Relaxed)
}

// ============================================================================
// GLOBAL ALLOCATOR
// ============================================================================

/// Global heap allocator for use with alloc crate
pub struct KernelAllocator;

unsafe impl GlobalAlloc for KernelAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        alloc(layout.size(), layout.align())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        free(ptr)
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        realloc(ptr, new_size, layout.align())
    }
}

// Global allocator is provided by nonos_kernel library
// The library's memory::heap::manager provides #[global_allocator]

// Local allocator instance for binary-specific heap operations
/// Static kernel allocator instance that can be used for binary-specific heap operations
pub static KERNEL_ALLOCATOR: KernelAllocator = KernelAllocator;
