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

pub mod constants;
pub mod descriptor;
pub mod heap;
pub mod parse;
pub mod pmm;
pub mod types;

pub use constants::{
    align_down, align_up, PhysAddr, VirtAddr, HEAP_BASE, HEAP_SIZE, MAX_PAGES, MAX_PHYS_MEM,
    PAGE_SHIFT, PAGE_SIZE, PHYS_MAP_BASE,
};
pub use descriptor::{MemoryDescriptor, MemoryRegion};
pub use heap::{
    alloc, free, init as heap_init, is_init as heap_is_init, realloc, stats as heap_stats,
    KernelAllocator, KERNEL_ALLOCATOR,
};
pub use pmm::{
    alloc_page, alloc_pages, alloc_pages_aligned, free_page, free_pages, free_pages_count,
    init as pmm_init, is_init as pmm_is_init, memory_stats, total_pages, used_pages,
};
pub use types::MemoryType;

use crate::sys::serial;

pub fn init(mmap_ptr: u64, mmap_entry_size: u32, mmap_entry_count: u32) {
    serial::println(b"[MEM] Initializing memory subsystem...");

    let total_usable = parse::parse_memory_map(mmap_ptr, mmap_entry_size, mmap_entry_count);

    serial::print(b"[MEM] Total usable memory: ");
    serial::print_dec(total_usable / 1024 / 1024);
    serial::println(b" MB");

    pmm::init(mmap_ptr, mmap_entry_size, mmap_entry_count);
    heap::init();

    serial::println(b"[MEM] Memory subsystem initialized");
}
