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

extern crate alloc;

use alloc::vec::Vec;

use crate::arch::x86_64::multiboot::error::MultibootError;
use crate::arch::x86_64::multiboot::memory_map::{EfiMemoryDescriptor, MemoryMapEntry};
use crate::arch::x86_64::multiboot::modules::BasicMemInfo;
use crate::arch::x86_64::multiboot::state::types::MultibootManager;

impl MultibootManager {
    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_basic_meminfo(
        &self,
        tag_ptr: *const u8,
    ) -> Option<BasicMemInfo> {
        // SAFETY: Caller guarantees tag_ptr points to valid basic meminfo tag.
        unsafe {
            #[repr(C)]
            struct BasicMemInfoTag {
                tag_type: u32,
                size: u32,
                mem_lower: u32,
                mem_upper: u32,
            }

            let tag = &*(tag_ptr as *const BasicMemInfoTag);
            Some(BasicMemInfo {
                mem_lower: tag.mem_lower,
                mem_upper: tag.mem_upper,
            })
        }
    }

    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_memory_map(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<Vec<MemoryMapEntry>, MultibootError> {
        // SAFETY: Caller guarantees tag_ptr points to valid memory map tag.
        unsafe {
            #[repr(C)]
            struct MemoryMapTag {
                tag_type: u32,
                size: u32,
                entry_size: u32,
                entry_version: u32,
            }

            let tag = &*(tag_ptr as *const MemoryMapTag);

            if tag.entry_size == 0 {
                return Err(MultibootError::MemoryMapError {
                    reason: "Zero entry size",
                });
            }

            let entries_size = size.saturating_sub(16);
            let num_entries = entries_size / tag.entry_size;
            let mut entries = Vec::with_capacity(num_entries as usize);

            let mut entry_ptr = tag_ptr.add(16);
            for _ in 0..num_entries {
                let entry = *(entry_ptr as *const MemoryMapEntry);
                entries.push(entry);
                entry_ptr = entry_ptr.add(tag.entry_size as usize);
            }

            Ok(entries)
        }
    }

    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_efi_memory_map(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<Vec<EfiMemoryDescriptor>, MultibootError> {
        // SAFETY: Caller guarantees tag_ptr points to valid EFI memory map tag.
        unsafe {
            #[repr(C)]
            struct EfiMemoryMapTag {
                tag_type: u32,
                size: u32,
                descriptor_size: u32,
                descriptor_version: u32,
            }

            let tag = &*(tag_ptr as *const EfiMemoryMapTag);

            if tag.descriptor_size == 0 {
                return Err(MultibootError::MemoryMapError {
                    reason: "Zero descriptor size",
                });
            }

            let entries_offset = 16u32;
            let entries_size = size.saturating_sub(entries_offset);
            let num_entries = entries_size / tag.descriptor_size;

            let mut entries = Vec::with_capacity(num_entries as usize);
            let mut entry_ptr = tag_ptr.add(entries_offset as usize);

            for _ in 0..num_entries {
                #[repr(C)]
                struct EfiMemDesc {
                    memory_type: u32,
                    padding: u32,
                    physical_start: u64,
                    virtual_start: u64,
                    number_of_pages: u64,
                    attribute: u64,
                }

                let desc = &*(entry_ptr as *const EfiMemDesc);
                entries.push(EfiMemoryDescriptor {
                    memory_type: desc.memory_type,
                    physical_start: desc.physical_start,
                    virtual_start: desc.virtual_start,
                    number_of_pages: desc.number_of_pages,
                    attribute: desc.attribute,
                });

                entry_ptr = entry_ptr.add(tag.descriptor_size as usize);
            }

            Ok(entries)
        }
    }
}
