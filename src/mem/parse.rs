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

use super::constants::PAGE_SIZE;
use super::descriptor::MemoryDescriptor;
use super::types::MemoryType;
use crate::sys::serial;

pub fn parse_memory_map(mmap_ptr: u64, entry_size: u32, entry_count: u32) -> u64 {
    let mut total_usable: u64 = 0;
    let mut total_pages: u64 = 0;

    if mmap_ptr == 0 {
        serial::println(b"[MEM] WARNING: No memory map provided!");
        return 0;
    }

    for i in 0..entry_count {
        let entry_addr = mmap_ptr + (i as u64) * (entry_size as u64);
        let entry = unsafe { &*(entry_addr as *const MemoryDescriptor) };
        let mem_type = MemoryType::from_u32_or_reserved(entry.mem_type);
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
