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
pub mod types;
pub mod descriptor;
pub mod parse;
pub mod pmm;
pub mod heap;

pub use constants::{
    PhysAddr, VirtAddr, PAGE_SIZE, PAGE_SHIFT, MAX_PHYS_MEM, MAX_PAGES,
    PHYS_MAP_BASE, HEAP_BASE, HEAP_SIZE, align_up, align_down,
};
pub use types::MemoryType;
pub use descriptor::{MemoryDescriptor, MemoryRegion};
pub use pmm::{
    init as pmm_init, alloc_page, alloc_pages, alloc_pages_aligned,
    free_page, free_pages, total_pages, free_pages_count, used_pages,
    memory_stats, is_init as pmm_is_init,
};
pub use heap::{
    init as heap_init, alloc, free, realloc, stats as heap_stats,
    is_init as heap_is_init, KernelAllocator, KERNEL_ALLOCATOR,
};

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
