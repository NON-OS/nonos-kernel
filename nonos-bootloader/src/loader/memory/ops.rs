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

extern crate alloc;

use crate::loader::errors::{LoaderError, LoaderResult};
use crate::loader::types::memory;
use crate::log::logger::{log_error, log_info};
use alloc::format;
use uefi::table::boot::{AllocateType, MemoryType};

use super::table::AllocationTable;

pub fn allocate_at_address(
    bs: &uefi::table::boot::BootServices,
    address: u64,
    pages: usize,
    table: &mut AllocationTable,
) -> LoaderResult<u64> {
    if address & (memory::PAGE_SIZE as u64 - 1) != 0 {
        return Err(LoaderError::AddressOutOfRange);
    }

    match bs.allocate_pages(
        AllocateType::Address(address),
        MemoryType::LOADER_DATA,
        pages,
    ) {
        Ok(addr) => {
            table.record(addr, pages)?;
            log_info(
                "memory",
                &format!("Allocated {} pages at fixed address 0x{:x}", pages, addr),
            );
            Ok(addr)
        }
        Err(e) => {
            log_error(
                "memory",
                &format!(
                    "Failed to allocate at 0x{:x} ({} pages): {:?}",
                    address,
                    pages,
                    e.status()
                ),
            );
            Err(LoaderError::AllocationFailed {
                addr: address,
                pages,
                status: e.status(),
            })
        }
    }
}

pub fn allocate_anywhere(
    bs: &uefi::table::boot::BootServices,
    pages: usize,
    table: &mut AllocationTable,
) -> LoaderResult<u64> {
    match bs.allocate_pages(AllocateType::AnyPages, MemoryType::LOADER_DATA, pages) {
        Ok(addr) => {
            table.record(addr, pages)?;
            log_info(
                "memory",
                &format!("Allocated {} pages at 0x{:x}", pages, addr),
            );
            Ok(addr)
        }
        Err(e) => {
            log_error(
                "memory",
                &format!("Failed to allocate {} pages: {:?}", pages, e.status()),
            );
            Err(LoaderError::AllocationFailed {
                addr: 0,
                pages,
                status: e.status(),
            })
        }
    }
}

pub fn allocate_below_4gb(
    bs: &uefi::table::boot::BootServices,
    pages: usize,
    table: &mut AllocationTable,
) -> LoaderResult<u64> {
    match bs.allocate_pages(
        AllocateType::MaxAddress(0xFFFF_FFFF),
        MemoryType::LOADER_DATA,
        pages,
    ) {
        Ok(addr) => {
            table.record(addr, pages)?;
            log_info(
                "memory",
                &format!("Allocated {} pages at 0x{:x} (below 4GB)", pages, addr),
            );
            Ok(addr)
        }
        Err(_) => allocate_anywhere(bs, pages, table),
    }
}
// ## SAFETY
pub unsafe fn zero_memory(addr: u64, size: usize) {
    if size > 0 {
        core::ptr::write_bytes(addr as *mut u8, 0, size);
    }
}

// ## SAFETY
pub unsafe fn copy_memory(src: *const u8, dst: u64, size: usize) {
    if size > 0 {
        core::ptr::copy_nonoverlapping(src, dst as *mut u8, size);
    }
}

pub fn pages_for_size(size: usize) -> usize {
    memory::pages_needed(size)
}

pub fn page_align_down(addr: u64) -> u64 {
    memory::page_align_down(addr)
}

pub fn page_align_up(addr: u64) -> u64 {
    memory::page_align_up(addr)
}

pub fn is_page_aligned(addr: u64) -> bool {
    (addr & (memory::PAGE_SIZE as u64 - 1)) == 0
}
