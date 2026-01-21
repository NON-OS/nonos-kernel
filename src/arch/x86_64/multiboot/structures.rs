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
use x86_64::PhysAddr;
use super::constants::{MULTIBOOT2_HEADER_MAGIC, MULTIBOOT2_ARCHITECTURE_I386, memory_type};

#[repr(C, align(8))]
pub struct Multiboot2Header {
    pub magic: u32,
    pub architecture: u32,
    pub header_length: u32,
    pub checksum: u32,
}

impl Multiboot2Header {
    pub const fn new(header_length: u32) -> Self {
        let checksum = (0u32)
            .wrapping_sub(MULTIBOOT2_HEADER_MAGIC)
            .wrapping_sub(MULTIBOOT2_ARCHITECTURE_I386)
            .wrapping_sub(header_length);
        Self {
            magic: MULTIBOOT2_HEADER_MAGIC,
            architecture: MULTIBOOT2_ARCHITECTURE_I386,
            header_length,
            checksum,
        }
    }

    pub const fn verify_checksum(&self) -> bool {
        self.magic
            .wrapping_add(self.architecture)
            .wrapping_add(self.header_length)
            .wrapping_add(self.checksum)
            == 0
    }
}

#[repr(C)]
pub struct Multiboot2Info {
    pub total_size: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct TagHeader {
    pub tag_type: u32,
    pub size: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct MemoryMapEntry {
    pub base_addr: u64,
    pub length: u64,
    pub entry_type: u32,
    pub reserved: u32,
}

impl MemoryMapEntry {
    pub const fn is_available(&self) -> bool {
        self.entry_type == memory_type::AVAILABLE
    }

    pub const fn is_acpi_reclaimable(&self) -> bool {
        self.entry_type == memory_type::ACPI_RECLAIMABLE
    }

    pub fn start_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr)
    }

    pub fn end_addr(&self) -> PhysAddr {
        PhysAddr::new(self.base_addr.saturating_add(self.length))
    }

    pub const fn type_name(&self) -> &'static str {
        memory_type::name(self.entry_type)
    }
}

#[derive(Debug, Clone)]
pub struct FramebufferInfo {
    pub addr: PhysAddr,
    pub pitch: u32,
    pub width: u32,
    pub height: u32,
    pub bpp: u8,
    pub framebuffer_type: FramebufferType,
    pub color_info: Option<ColorInfo>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FramebufferType {
    Indexed,
    DirectRgb,
    EgaText,
    Unknown(u8),
}

impl From<u8> for FramebufferType {
    fn from(val: u8) -> Self {
        match val {
            0 => Self::Indexed,
            1 => Self::DirectRgb,
            2 => Self::EgaText,
            other => Self::Unknown(other),
        }
    }
}

#[derive(Debug, Clone, Copy)]
pub struct ColorInfo {
    pub red_position: u8,
    pub red_mask_size: u8,
    pub green_position: u8,
    pub green_mask_size: u8,
    pub blue_position: u8,
    pub blue_mask_size: u8,
}

#[derive(Debug, Clone)]
pub struct ModuleInfo {
    pub mod_start: PhysAddr,
    pub mod_end: PhysAddr,
    pub cmdline: String,
}

#[derive(Debug, Clone, Copy)]
pub struct BasicMemInfo {
    pub mem_lower: u32,
    pub mem_upper: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct BiosBootDevice {
    pub biosdev: u32,
    pub partition: u32,
    pub sub_partition: u32,
}

#[derive(Debug, Clone, Copy)]
pub struct VbeInfo {
    pub vbe_mode: u16,
    pub vbe_interface_seg: u16,
    pub vbe_interface_off: u16,
    pub vbe_interface_len: u16,
}

#[derive(Debug, Clone)]
pub struct ElfSections {
    pub num: u32,
    pub entsize: u32,
    pub shndx: u32,
    pub sections: alloc::vec::Vec<ElfSection>,
}

#[derive(Debug, Clone)]
pub struct ElfSection {
    pub name: u32,
    pub section_type: u32,
    pub flags: u64,
    pub addr: u64,
    pub offset: u64,
    pub size: u64,
    pub link: u32,
    pub info: u32,
    pub addralign: u64,
    pub entsize: u64,
}

#[derive(Debug, Clone, Copy)]
pub struct ApmTable {
    pub version: u16,
    pub cseg: u16,
    pub offset: u32,
    pub cseg_16: u16,
    pub dseg: u16,
    pub flags: u16,
    pub cseg_len: u16,
    pub cseg_16_len: u16,
    pub dseg_len: u16,
}

#[derive(Debug, Clone)]
pub struct AcpiRsdp {
    pub revision: u8,
    pub rsdp_address: PhysAddr,
    pub is_xsdt: bool,
}

#[derive(Debug, Clone)]
pub struct SmbiosInfo {
    pub major: u8,
    pub minor: u8,
    pub tables: alloc::vec::Vec<u8>,
}

#[derive(Debug, Clone, Copy)]
pub struct EfiMemoryDescriptor {
    pub type_: u32,
    pub phys_addr: u64,
    pub virt_addr: u64,
    pub num_pages: u64,
    pub attribute: u64,
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
