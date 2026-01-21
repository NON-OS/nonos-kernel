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

pub const MULTIBOOT2_HEADER_MAGIC: u32 = 0xE85250D6;
pub const MULTIBOOT2_BOOTLOADER_MAGIC: u32 = 0x36D76289;
pub const MULTIBOOT2_ARCHITECTURE_I386: u32 = 0;

pub mod tag {
    pub const END: u32 = 0;
    pub const CMDLINE: u32 = 1;
    pub const BOOTLOADER_NAME: u32 = 2;
    pub const MODULE: u32 = 3;
    pub const BASIC_MEMINFO: u32 = 4;
    pub const BIOS_BOOT_DEVICE: u32 = 5;
    pub const MEMORY_MAP: u32 = 6;
    pub const VBE_INFO: u32 = 7;
    pub const FRAMEBUFFER: u32 = 8;
    pub const ELF_SECTIONS: u32 = 9;
    pub const APM: u32 = 10;
    pub const EFI32_SYSTEM_TABLE: u32 = 11;
    pub const EFI64_SYSTEM_TABLE: u32 = 12;
    pub const SMBIOS: u32 = 13;
    pub const ACPI_OLD: u32 = 14;
    pub const ACPI_NEW: u32 = 15;
    pub const NETWORK: u32 = 16;
    pub const EFI_MEMORY_MAP: u32 = 17;
    pub const EFI_BOOT_SERVICES: u32 = 18;
    pub const EFI32_IMAGE_HANDLE: u32 = 19;
    pub const EFI64_IMAGE_HANDLE: u32 = 20;
    pub const IMAGE_LOAD_BASE: u32 = 21;

    pub const fn name(tag_type: u32) -> &'static str {
        match tag_type {
            END => "End",
            CMDLINE => "Command Line",
            BOOTLOADER_NAME => "Bootloader Name",
            MODULE => "Module",
            BASIC_MEMINFO => "Basic Memory Info",
            BIOS_BOOT_DEVICE => "BIOS Boot Device",
            MEMORY_MAP => "Memory Map",
            VBE_INFO => "VBE Info",
            FRAMEBUFFER => "Framebuffer",
            ELF_SECTIONS => "ELF Sections",
            APM => "APM Table",
            EFI32_SYSTEM_TABLE => "EFI32 System Table",
            EFI64_SYSTEM_TABLE => "EFI64 System Table",
            SMBIOS => "SMBIOS",
            ACPI_OLD => "ACPI Old RSDP",
            ACPI_NEW => "ACPI New RSDP",
            NETWORK => "Network Info",
            EFI_MEMORY_MAP => "EFI Memory Map",
            EFI_BOOT_SERVICES => "EFI Boot Services",
            EFI32_IMAGE_HANDLE => "EFI32 Image Handle",
            EFI64_IMAGE_HANDLE => "EFI64 Image Handle",
            IMAGE_LOAD_BASE => "Image Load Base",
            _ => "Unknown",
        }
    }
}

pub mod memory_type {
    pub const AVAILABLE: u32 = 1;
    pub const RESERVED: u32 = 2;
    pub const ACPI_RECLAIMABLE: u32 = 3;
    pub const ACPI_NVS: u32 = 4;
    pub const BAD_MEMORY: u32 = 5;

    pub const fn name(mem_type: u32) -> &'static str {
        match mem_type {
            AVAILABLE => "Available",
            RESERVED => "Reserved",
            ACPI_RECLAIMABLE => "ACPI Reclaimable",
            ACPI_NVS => "ACPI NVS",
            BAD_MEMORY => "Bad Memory",
            _ => "Unknown",
        }
    }
}
