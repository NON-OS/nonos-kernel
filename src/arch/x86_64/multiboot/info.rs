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

use alloc::string::String;
use alloc::vec::Vec;
use x86_64::{PhysAddr, VirtAddr};

use super::framebuffer::FramebufferInfo;
use super::memory_map::{EfiMemoryDescriptor, MemoryMapEntry};
use super::modules::{
    AcpiRsdp, ApmTable, BasicMemInfo, BiosBootDevice, ElfSections, ModuleInfo, SmbiosInfo, VbeInfo,
};

#[derive(Debug, Clone)]
pub struct ParsedMultibootInfo {
    pub info_addr: VirtAddr,
    pub total_size: u32,
    pub cmdline: Option<String>,
    pub bootloader_name: Option<String>,
    pub memory_map: Vec<MemoryMapEntry>,
    pub framebuffer: Option<FramebufferInfo>,
    pub modules: Vec<ModuleInfo>,
    pub basic_meminfo: Option<BasicMemInfo>,
    pub boot_device: Option<BiosBootDevice>,
    pub vbe_info: Option<VbeInfo>,
    pub elf_sections: Option<ElfSections>,
    pub apm: Option<ApmTable>,
    pub acpi_rsdp: Option<AcpiRsdp>,
    pub smbios: Option<SmbiosInfo>,
    pub efi64_system_table: Option<u64>,
    pub efi32_system_table: Option<u32>,
    pub efi_memory_map: Option<Vec<EfiMemoryDescriptor>>,
    pub efi_boot_services_not_terminated: bool,
    pub efi64_image_handle: Option<u64>,
    pub efi32_image_handle: Option<u32>,
    pub image_load_base: Option<PhysAddr>,
}

impl ParsedMultibootInfo {
    pub fn total_available_memory(&self) -> u64 {
        self.memory_map
            .iter()
            .filter(|e| e.is_available())
            .map(|e| e.length)
            .sum()
    }

    pub fn total_reserved_memory(&self) -> u64 {
        self.memory_map
            .iter()
            .filter(|e| !e.is_available())
            .map(|e| e.length)
            .sum()
    }

    pub fn largest_available_region(&self) -> Option<&MemoryMapEntry> {
        self.memory_map
            .iter()
            .filter(|e| e.is_available())
            .max_by_key(|e| e.length)
    }

    pub fn has_acpi(&self) -> bool {
        self.acpi_rsdp.is_some()
    }

    pub fn is_efi_boot(&self) -> bool {
        self.efi64_system_table.is_some() || self.efi32_system_table.is_some()
    }
}
