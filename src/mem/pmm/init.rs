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

use super::super::types::MemoryType;
use super::super::{MemoryDescriptor, PAGE_SIZE};
use super::bitmap::mark_page_free;
use super::state::{FREE_PAGES, MAX_BITMAP_PAGES, MAX_PHYS_ADDR, PMM_INIT, TOTAL_PAGES};
use crate::sys::serial;
use core::sync::atomic::Ordering;

pub fn init(mmap_ptr: u64, entry_size: u32, entry_count: u32) {
    if PMM_INIT.load(Ordering::Relaxed) != 0 {
        return;
    }

    serial::println(b"[PMM] Initializing physical memory manager...");

    let max_addr = find_max_address(mmap_ptr, entry_size, entry_count);
    MAX_PHYS_ADDR.store(max_addr, Ordering::SeqCst);

    let max_pages = (max_addr / PAGE_SIZE as u64).min(MAX_BITMAP_PAGES as u64) as usize;
    TOTAL_PAGES.store(max_pages, Ordering::SeqCst);

    serial::print(b"[PMM] Max physical address: 0x");
    serial::print_hex(max_addr);
    serial::println(b"");

    let freed_pages = mark_usable_regions(mmap_ptr, entry_size, entry_count);
    FREE_PAGES.store(freed_pages, Ordering::SeqCst);
    PMM_INIT.store(1, Ordering::SeqCst);

    serial::print(b"[PMM] Free pages: ");
    serial::print_dec(freed_pages as u64);
    serial::print(b" (");
    serial::print_dec((freed_pages * PAGE_SIZE / 1024 / 1024) as u64);
    serial::println(b" MB)");
}

fn find_max_address(mmap_ptr: u64, entry_size: u32, entry_count: u32) -> u64 {
    let mut max_addr: u64 = 0;

    for i in 0..entry_count {
        let entry_addr = mmap_ptr + (i as u64) * (entry_size as u64);
        let entry = unsafe { &*(entry_addr as *const MemoryDescriptor) };
        let region_end = entry.phys_start + (entry.num_pages * PAGE_SIZE as u64);
        if region_end > max_addr {
            max_addr = region_end;
        }
    }

    max_addr
}

fn mark_usable_regions(mmap_ptr: u64, entry_size: u32, entry_count: u32) -> usize {
    let mut freed_pages: usize = 0;

    for i in 0..entry_count {
        let entry_addr = mmap_ptr + (i as u64) * (entry_size as u64);
        let entry = unsafe { &*(entry_addr as *const MemoryDescriptor) };
        let mem_type = MemoryType::from_u32_or_reserved(entry.mem_type);

        if mem_type == MemoryType::Conventional {
            freed_pages += mark_conventional_region(entry);
        }
    }

    freed_pages
}

fn mark_conventional_region(entry: &MemoryDescriptor) -> usize {
    let start_page = (entry.phys_start / PAGE_SIZE as u64) as usize;
    let num_pages = entry.num_pages as usize;

    let safe_start = if entry.phys_start < 0x10_0000 {
        let skip = (0x10_0000 - entry.phys_start) / PAGE_SIZE as u64;
        if skip >= entry.num_pages {
            return 0;
        }
        start_page + skip as usize
    } else {
        start_page
    };

    let safe_count = num_pages.saturating_sub(safe_start - start_page);
    let mut freed = 0;

    for page in safe_start..(safe_start + safe_count) {
        if page < MAX_BITMAP_PAGES {
            mark_page_free(page);
            freed += 1;
        }
    }

    freed
}
