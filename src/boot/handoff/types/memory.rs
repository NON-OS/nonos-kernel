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

pub mod memory_type {
    pub const RESERVED: u32 = 0;
    pub const LOADER_CODE: u32 = 1;
    pub const LOADER_DATA: u32 = 2;
    pub const BOOT_SERVICES_CODE: u32 = 3;
    pub const BOOT_SERVICES_DATA: u32 = 4;
    pub const RUNTIME_SERVICES_CODE: u32 = 5;
    pub const RUNTIME_SERVICES_DATA: u32 = 6;
    pub const CONVENTIONAL: u32 = 7;
    pub const UNUSABLE: u32 = 8;
    pub const ACPI_RECLAIM: u32 = 9;
    pub const ACPI_NVS: u32 = 10;
    pub const MMIO: u32 = 11;
    pub const MMIO_PORT_SPACE: u32 = 12;
    pub const PAL_CODE: u32 = 13;
    pub const PERSISTENT: u32 = 14;
}

/*
 * Memory map entry layout must match bootloader's MemoryMapEntry in exit.rs.
 * The _pad field aligns physical_start to 8 bytes, matching EFI_MEMORY_DESCRIPTOR.
 * Without this padding the kernel reads shifted garbage and hangs on real hardware.
 */
#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct MemoryMapEntry {
    pub memory_type: u32,
    pub _pad: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub page_count: u64,
    pub attribute: u64,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct MemoryMap {
    pub ptr: u64,
    pub entry_size: u32,
    pub entry_count: u32,
    pub desc_version: u32,
}

impl MemoryMap {
    // SAFETY: Caller must ensure ptr points to valid MemoryMapEntry array
    pub unsafe fn entries(&self) -> &[MemoryMapEntry] { unsafe {
        if self.ptr == 0 || self.entry_count == 0 {
            return &[];
        }
        core::slice::from_raw_parts(self.ptr as *const MemoryMapEntry, self.entry_count as usize)
    }}

    // SAFETY: Caller must ensure ptr points to valid MemoryMapEntry array
    pub unsafe fn usable_regions(&self) -> impl Iterator<Item = (u64, u64)> + '_ { unsafe {
        self.entries()
            .iter()
            .filter(|e| e.memory_type == memory_type::CONVENTIONAL)
            .map(|e| (e.physical_start, e.physical_start + e.page_count * 4096))
    }}

    // SAFETY: Caller must ensure ptr points to valid MemoryMapEntry array
    pub unsafe fn total_usable_memory(&self) -> u64 { unsafe {
        self.entries()
            .iter()
            .filter(|e| e.memory_type == memory_type::CONVENTIONAL)
            .map(|e| e.page_count * 4096)
            .sum()
    }}
}
