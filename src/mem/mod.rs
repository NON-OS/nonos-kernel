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

//! NONOS Memory Management Subsystem
//! Physical memory manager, virtual memory manager, and kernel heap
//!
//! Memory Layout (x86_64 Long Mode):
//! 0x0000_0000_0000_0000 - 0x0000_7FFF_FFFF_FFFF : User space (128 TB canonical)
//! 0xFFFF_8000_0000_0000 - 0xFFFF_8000_3FFF_FFFF : Physical memory direct mapping (1 GB)
//! 0xFFFF_8000_4000_0000 - 0xFFFF_8000_7FFF_FFFF : Kernel heap (1 GB)
//! 0xFFFF_FFFF_8000_0000 - 0xFFFF_FFFF_FFFF_FFFF : Kernel code/data (2 GB)

pub mod pmm;
pub mod heap;

// PMM exports - physical memory manager
pub use pmm::{
    init as pmm_init, alloc_page, alloc_pages, alloc_pages_aligned, free_page, free_pages,
    total_pages, free_pages_count, used_pages, memory_stats, is_init as pmm_is_init,
};

// Heap exports - kernel heap allocator
pub use heap::{
    init as heap_init, alloc, free, realloc, stats as heap_stats, is_init as heap_is_init,
    KernelAllocator, KERNEL_ALLOCATOR,
};

use crate::sys::serial;

/// Physical address type
pub type PhysAddr = u64;

/// Virtual address type
pub type VirtAddr = u64;

/// Page size (4 KB)
pub const PAGE_SIZE: usize = 4096;

/// Page shift (log2 of PAGE_SIZE)
pub const PAGE_SHIFT: usize = 12;

/// Maximum physical memory we'll manage (1 GB for now)
pub const MAX_PHYS_MEM: usize = 1024 * 1024 * 1024;

/// Number of pages we can manage
pub const MAX_PAGES: usize = MAX_PHYS_MEM / PAGE_SIZE;

/// Direct physical memory mapping base
pub const PHYS_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;

/// Kernel heap base
pub const HEAP_BASE: u64 = 0xFFFF_8000_4000_0000;

/// Kernel heap size (256 MB)
pub const HEAP_SIZE: usize = 256 * 1024 * 1024;

/// UEFI Memory Type (from UEFI spec)
#[repr(u32)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryType {
    Reserved = 0,
    LoaderCode = 1,
    LoaderData = 2,
    BootServicesCode = 3,
    BootServicesData = 4,
    RuntimeServicesCode = 5,
    RuntimeServicesData = 6,
    Conventional = 7,          // Free memory we can use
    Unusable = 8,
    ACPIReclaim = 9,
    ACPINvs = 10,
    MemoryMappedIO = 11,
    MemoryMappedIOPortSpace = 12,
    PalCode = 13,
    PersistentMemory = 14,
    MaxMemoryType = 15,
}

impl MemoryType {
    /// Check if this memory type is usable (can be allocated)
    pub fn is_usable(&self) -> bool {
        matches!(self,
            MemoryType::Conventional |
            MemoryType::BootServicesCode |
            MemoryType::BootServicesData |
            MemoryType::LoaderCode |
            MemoryType::LoaderData
        )
    }
}

/// UEFI Memory Descriptor (must match bootloader's EfiMemoryDescriptor)
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryDescriptor {
    pub mem_type: u32,
    pub phys_start: u64,
    pub virt_start: u64,
    pub num_pages: u64,
    pub attribute: u64,
}

/// Memory region info for internal use
#[derive(Debug, Clone, Copy)]
pub struct MemoryRegion {
    pub start: PhysAddr,
    pub end: PhysAddr,
    pub usable: bool,
}

/// Initialize the memory subsystem with UEFI memory map
pub fn init(mmap_ptr: u64, mmap_entry_size: u32, mmap_entry_count: u32) {
    serial::println(b"[MEM] Initializing memory subsystem...");

    // Parse memory map from bootloader
    let total_usable = parse_memory_map(mmap_ptr, mmap_entry_size, mmap_entry_count);

    serial::print(b"[MEM] Total usable memory: ");
    serial::print_dec(total_usable / 1024 / 1024);
    serial::println(b" MB");

    // Initialize physical memory manager
    pmm::init(mmap_ptr, mmap_entry_size, mmap_entry_count);

    // Initialize kernel heap
    heap::init();

    serial::println(b"[MEM] Memory subsystem initialized");
}

/// Parse UEFI memory map and return total usable memory
fn parse_memory_map(mmap_ptr: u64, entry_size: u32, entry_count: u32) -> u64 {
    let mut total_usable: u64 = 0;
    let mut total_pages: u64 = 0;

    if mmap_ptr == 0 {
        serial::println(b"[MEM] WARNING: No memory map provided!");
        return 0;
    }

    for i in 0..entry_count {
        let entry_addr = mmap_ptr + (i as u64) * (entry_size as u64);
        let entry = unsafe { &*(entry_addr as *const MemoryDescriptor) };

        let mem_type = if entry.mem_type < 15 {
            unsafe { core::mem::transmute::<u32, MemoryType>(entry.mem_type) }
        } else {
            MemoryType::Reserved
        };

        let region_size = entry.num_pages * PAGE_SIZE as u64;
        total_pages += entry.num_pages;

        if mem_type.is_usable() {
            total_usable += region_size;
        }
    }

    serial::print(b"[MEM] Memory map: ");
    serial::print_dec(entry_count as u64);
    serial::print(b" entries, ");
    serial::print_dec(total_pages);
    serial::println(b" pages total");

    total_usable
}

/// Align address up to page boundary
pub const fn align_up(addr: u64, align: u64) -> u64 {
    (addr + align - 1) & !(align - 1)
}

/// Align address down to page boundary
pub const fn align_down(addr: u64, align: u64) -> u64 {
    addr & !(align - 1)
}
