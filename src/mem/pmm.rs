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

//! Physical Memory Manager (PMM)
//! Bitmap-based page frame allocator for physical memory
//!
//! This allocator manages physical memory pages using a bitmap where each bit
//! represents a 4KB page frame. A bit value of 1 means the page is allocated,
//! 0 means it's free.

use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use crate::sys::serial;
use super::{PhysAddr, MemoryDescriptor, MemoryType, PAGE_SIZE, PAGE_SHIFT};

/// Maximum pages we can track (256K pages = 1GB)
const MAX_BITMAP_PAGES: usize = 256 * 1024;

/// Bitmap size in u64 words (each u64 tracks 64 pages)
const BITMAP_SIZE: usize = MAX_BITMAP_PAGES / 64;

/// Static bitmap for page allocation
/// Each bit represents a 4KB page: 1 = allocated, 0 = free
static mut PAGE_BITMAP: [AtomicU64; BITMAP_SIZE] = {
    const INIT: AtomicU64 = AtomicU64::new(0xFFFF_FFFF_FFFF_FFFF); // All allocated by default
    [INIT; BITMAP_SIZE]
};

/// Total number of physical pages available
static TOTAL_PAGES: AtomicUsize = AtomicUsize::new(0);

/// Number of free pages available
static FREE_PAGES: AtomicUsize = AtomicUsize::new(0);

/// Highest usable physical address
static MAX_PHYS_ADDR: AtomicU64 = AtomicU64::new(0);

/// PMM initialization flag
static PMM_INIT: AtomicUsize = AtomicUsize::new(0);

/// Initialize the physical memory manager from UEFI memory map
pub fn init(mmap_ptr: u64, entry_size: u32, entry_count: u32) {
    if PMM_INIT.load(Ordering::Relaxed) != 0 {
        return; // Already initialized
    }

    serial::println(b"[PMM] Initializing physical memory manager...");

    // First pass: find max physical address and total memory
    let mut max_addr: u64 = 0;
    let mut _total_usable: u64 = 0;

    for i in 0..entry_count {
        let entry_addr = mmap_ptr + (i as u64) * (entry_size as u64);
        let entry = unsafe { &*(entry_addr as *const MemoryDescriptor) };

        let region_end = entry.phys_start + (entry.num_pages * PAGE_SIZE as u64);
        if region_end > max_addr {
            max_addr = region_end;
        }

        let mem_type = if entry.mem_type < 15 {
            unsafe { core::mem::transmute::<u32, MemoryType>(entry.mem_type) }
        } else {
            MemoryType::Reserved
        };

        if mem_type.is_usable() {
            _total_usable += entry.num_pages * PAGE_SIZE as u64;
        }
    }

    MAX_PHYS_ADDR.store(max_addr, Ordering::SeqCst);

    // Limit to what our bitmap can track
    let max_pages = (max_addr / PAGE_SIZE as u64).min(MAX_BITMAP_PAGES as u64) as usize;
    TOTAL_PAGES.store(max_pages, Ordering::SeqCst);

    serial::print(b"[PMM] Max physical address: 0x");
    serial::print_hex(max_addr);
    serial::println(b"");

    // Second pass: mark usable regions as free
    let mut freed_pages: usize = 0;

    for i in 0..entry_count {
        let entry_addr = mmap_ptr + (i as u64) * (entry_size as u64);
        let entry = unsafe { &*(entry_addr as *const MemoryDescriptor) };

        let mem_type = if entry.mem_type < 15 {
            unsafe { core::mem::transmute::<u32, MemoryType>(entry.mem_type) }
        } else {
            MemoryType::Reserved
        };

        // Only free conventional memory (skip boot services for now)
        if mem_type == MemoryType::Conventional {
            let start_page = (entry.phys_start / PAGE_SIZE as u64) as usize;
            let num_pages = entry.num_pages as usize;

            // Skip low memory (first 1MB) - often contains BIOS/UEFI data
            let safe_start = if entry.phys_start < 0x10_0000 {
                let skip = (0x10_0000 - entry.phys_start) / PAGE_SIZE as u64;
                if skip >= entry.num_pages {
                    continue;
                }
                start_page + skip as usize
            } else {
                start_page
            };

            let safe_count = num_pages.saturating_sub(safe_start - start_page);

            for page in safe_start..(safe_start + safe_count) {
                if page < MAX_BITMAP_PAGES {
                    mark_page_free(page);
                    freed_pages += 1;
                }
            }
        }
    }

    FREE_PAGES.store(freed_pages, Ordering::SeqCst);
    PMM_INIT.store(1, Ordering::SeqCst);

    serial::print(b"[PMM] Free pages: ");
    serial::print_dec(freed_pages as u64);
    serial::print(b" (");
    serial::print_dec((freed_pages * PAGE_SIZE / 1024 / 1024) as u64);
    serial::println(b" MB)");
}

/// Mark a page as allocated
fn mark_page_allocated(page: usize) {
    let word_idx = page / 64;
    let bit_idx = page % 64;
    if word_idx < BITMAP_SIZE {
        unsafe {
            PAGE_BITMAP[word_idx].fetch_or(1u64 << bit_idx, Ordering::SeqCst);
        }
    }
}

/// Mark a page as free
fn mark_page_free(page: usize) {
    let word_idx = page / 64;
    let bit_idx = page % 64;
    if word_idx < BITMAP_SIZE {
        unsafe {
            PAGE_BITMAP[word_idx].fetch_and(!(1u64 << bit_idx), Ordering::SeqCst);
        }
    }
}

/// Check if a page is allocated
fn is_page_allocated(page: usize) -> bool {
    let word_idx = page / 64;
    let bit_idx = page % 64;
    if word_idx < BITMAP_SIZE {
        unsafe {
            PAGE_BITMAP[word_idx].load(Ordering::Relaxed) & (1u64 << bit_idx) != 0
        }
    } else {
        true // Out of range = allocated
    }
}

/// Allocate a single physical page
/// Returns the physical address of the allocated page, or None if out of memory
pub fn alloc_page() -> Option<PhysAddr> {
    alloc_pages(1)
}

/// Allocate multiple contiguous physical pages
/// Returns the physical address of the first page, or None if out of memory
pub fn alloc_pages(count: usize) -> Option<PhysAddr> {
    if count == 0 {
        return None;
    }

    let total = TOTAL_PAGES.load(Ordering::Relaxed);

    // Search for contiguous free pages
    let mut start_page = 0usize;
    'outer: while start_page + count <= total {
        // Quick check: find first word with any free bits
        let word_start = start_page / 64;

        for word_idx in word_start..BITMAP_SIZE {
            let word = unsafe { PAGE_BITMAP[word_idx].load(Ordering::Relaxed) };

            // All pages in this word are allocated
            if word == 0xFFFF_FFFF_FFFF_FFFF {
                continue;
            }

            // Found a word with free pages, search within
            for bit in 0..64 {
                let page = word_idx * 64 + bit;
                if page >= total {
                    return None; // Reached end
                }

                // Check if we have 'count' contiguous free pages starting here
                for offset in 0..count {
                    if is_page_allocated(page + offset) {
                        start_page = page + offset + 1;
                        continue 'outer;
                    }
                }

                // All pages are free (we would have continued 'outer otherwise)
                // Found! Mark all pages as allocated
                for offset in 0..count {
                    mark_page_allocated(page + offset);
                }

                // Update free count
                FREE_PAGES.fetch_sub(count, Ordering::SeqCst);

                return Some((page as u64) << PAGE_SHIFT);
            }
        }

        break; // Searched entire bitmap
    }

    None // Out of memory
}

/// Allocate pages aligned to a specific boundary
/// alignment must be a power of 2 and >= PAGE_SIZE
pub fn alloc_pages_aligned(count: usize, alignment: usize) -> Option<PhysAddr> {
    if count == 0 || alignment < PAGE_SIZE || !alignment.is_power_of_two() {
        return None;
    }

    let align_pages = alignment / PAGE_SIZE;
    let total = TOTAL_PAGES.load(Ordering::Relaxed);

    // Search for aligned contiguous free pages
    let mut page = 0usize;
    while page + count <= total {
        // Align to boundary
        page = (page + align_pages - 1) & !(align_pages - 1);

        if page + count > total {
            break;
        }

        // Check if all pages are free
        let mut all_free = true;
        for offset in 0..count {
            if is_page_allocated(page + offset) {
                all_free = false;
                page += offset + 1;
                break;
            }
        }

        if all_free {
            // Mark as allocated
            for offset in 0..count {
                mark_page_allocated(page + offset);
            }
            FREE_PAGES.fetch_sub(count, Ordering::SeqCst);
            return Some((page as u64) << PAGE_SHIFT);
        }
    }

    None
}

/// Free a single physical page
pub fn free_page(addr: PhysAddr) {
    free_pages(addr, 1);
}

/// Free multiple contiguous physical pages
pub fn free_pages(addr: PhysAddr, count: usize) {
    if count == 0 {
        return;
    }

    let start_page = (addr >> PAGE_SHIFT) as usize;

    for offset in 0..count {
        let page = start_page + offset;
        if page < MAX_BITMAP_PAGES {
            // Only free if actually allocated (prevent double-free)
            if is_page_allocated(page) {
                mark_page_free(page);
                FREE_PAGES.fetch_add(1, Ordering::SeqCst);
            }
        }
    }
}

/// Get total number of pages
pub fn total_pages() -> usize {
    TOTAL_PAGES.load(Ordering::Relaxed)
}

/// Get number of free pages
pub fn free_pages_count() -> usize {
    FREE_PAGES.load(Ordering::Relaxed)
}

/// Get used pages
pub fn used_pages() -> usize {
    total_pages().saturating_sub(free_pages_count())
}

/// Get memory statistics
pub fn memory_stats() -> (usize, usize, usize) {
    let total = total_pages() * PAGE_SIZE;
    let free = free_pages_count() * PAGE_SIZE;
    let used = total.saturating_sub(free);
    (total, used, free)
}

/// Check if PMM is initialized
pub fn is_init() -> bool {
    PMM_INIT.load(Ordering::Relaxed) != 0
}
