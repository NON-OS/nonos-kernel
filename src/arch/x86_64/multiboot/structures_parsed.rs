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
use super::structures_acpi::{AcpiRsdp, EfiMemoryDescriptor, SmbiosInfo};
use super::structures_elf::{ApmTable, ElfSections};
use super::structures_fb::{FramebufferInfo, VbeInfo};
use super::structures_memory::{BasicMemInfo, BiosBootDevice, MemoryMapEntry};
use alloc::string::String;
use crate::memory::addr::PhysAddr;

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub mod_start: PhysAddr,
    pub mod_end: PhysAddr,
    pub cmdline: String,
}

#[derive(Debug, Clone, Default)]
pub struct ParsedMultibootInfo {
    pub cmdline: Option<String>,
    pub bootloader: Option<String>,
    pub memory_map: alloc::vec::Vec<MemoryMapEntry>,
    pub framebuffer: Option<FramebufferInfo>,
    pub modules: alloc::vec::Vec<ModuleInfo>,
    pub basic_mem: Option<BasicMemInfo>,
    pub bios_boot: Option<BiosBootDevice>,
    pub vbe: Option<VbeInfo>,
    pub elf_sections: Option<ElfSections>,
    pub apm: Option<ApmTable>,
    pub acpi_rsdp: Option<AcpiRsdp>,
    pub smbios: Option<SmbiosInfo>,
    pub efi_system_table_32: Option<u32>,
    pub efi_system_table_64: Option<u64>,
    pub efi_memory_map: Option<alloc::vec::Vec<EfiMemoryDescriptor>>,
    pub efi_boot_services_not_terminated: bool,
    pub image_load_base: Option<u64>,
}
