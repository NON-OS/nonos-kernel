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
use core::sync::atomic::Ordering;
use x86_64::VirtAddr;

use crate::arch::x86_64::multiboot::constants::tag;
use crate::arch::x86_64::multiboot::error::MultibootError;
use crate::arch::x86_64::multiboot::header::{Multiboot2Info, TagHeader};
use crate::arch::x86_64::multiboot::info::ParsedMultibootInfo;
use crate::arch::x86_64::multiboot::state::types::MultibootManager;

impl MultibootManager {
    pub(in crate::arch::x86_64::multiboot::state) unsafe fn parse_info(
        &self,
        info_addr: VirtAddr,
    ) -> Result<ParsedMultibootInfo, MultibootError> {
        // SAFETY: Caller guarantees info_addr points to valid Multiboot2 structure.
        unsafe {
            if info_addr.as_u64() % 8 != 0 {
                return Err(MultibootError::AlignmentError {
                    expected: 8,
                    found: (info_addr.as_u64() % 8) as usize,
                });
            }

            let info = &*info_addr.as_ptr::<Multiboot2Info>();

            if info.total_size < 8 {
                return Err(MultibootError::InvalidInfoSize {
                    size: info.total_size,
                });
            }

            let mut parsed = ParsedMultibootInfo {
                info_addr,
                total_size: info.total_size,
                cmdline: None,
                bootloader_name: None,
                memory_map: Vec::new(),
                framebuffer: None,
                modules: Vec::new(),
                basic_meminfo: None,
                boot_device: None,
                vbe_info: None,
                elf_sections: None,
                apm: None,
                acpi_rsdp: None,
                smbios: None,
                efi64_system_table: None,
                efi32_system_table: None,
                efi_memory_map: None,
                efi_boot_services_not_terminated: false,
                efi64_image_handle: None,
                efi32_image_handle: None,
                image_load_base: None,
            };

            let mut tag_ptr = (info_addr + 8u64).as_ptr::<u8>();
            let end_ptr = (info_addr + info.total_size as u64).as_ptr::<u8>();

            while tag_ptr < end_ptr {
                let tag_header = &*(tag_ptr as *const TagHeader);

                if tag_header.tag_type == tag::END && tag_header.size == 8 {
                    break;
                }

                self.stats.tags_processed.fetch_add(1, Ordering::SeqCst);

                match tag_header.tag_type {
                    tag::CMDLINE => {
                        parsed.cmdline = self.parse_string_tag(tag_ptr, tag_header.size);
                    }
                    tag::BOOTLOADER_NAME => {
                        parsed.bootloader_name = self.parse_string_tag(tag_ptr, tag_header.size);
                    }
                    tag::MODULE => {
                        if let Ok(module) = self.parse_module(tag_ptr, tag_header.size) {
                            parsed.modules.push(module);
                            self.stats.modules_parsed.fetch_add(1, Ordering::SeqCst);
                        }
                    }
                    tag::BASIC_MEMINFO => {
                        parsed.basic_meminfo = self.parse_basic_meminfo(tag_ptr);
                    }
                    tag::BIOS_BOOT_DEVICE => {
                        parsed.boot_device = self.parse_boot_device(tag_ptr);
                    }
                    tag::MEMORY_MAP => {
                        if let Ok(entries) = self.parse_memory_map(tag_ptr, tag_header.size) {
                            self.stats
                                .memory_entries_parsed
                                .fetch_add(entries.len() as u64, Ordering::SeqCst);
                            parsed.memory_map = entries;
                        }
                    }
                    tag::VBE_INFO => {
                        parsed.vbe_info = self.parse_vbe_info(tag_ptr, tag_header.size);
                    }
                    tag::FRAMEBUFFER => {
                        if let Ok(fb) = self.parse_framebuffer(tag_ptr, tag_header.size) {
                            parsed.framebuffer = Some(fb);
                        }
                    }
                    tag::ELF_SECTIONS => {
                        if let Ok(elf) = self.parse_elf_sections(tag_ptr, tag_header.size) {
                            parsed.elf_sections = Some(elf);
                        }
                    }
                    tag::APM => {
                        parsed.apm = self.parse_apm(tag_ptr);
                    }
                    tag::EFI32_SYSTEM_TABLE => {
                        parsed.efi32_system_table = self.parse_efi32_ptr(tag_ptr);
                    }
                    tag::EFI64_SYSTEM_TABLE => {
                        parsed.efi64_system_table = self.parse_efi64_ptr(tag_ptr);
                    }
                    tag::SMBIOS => {
                        if let Ok(smbios) = self.parse_smbios(tag_ptr, tag_header.size) {
                            parsed.smbios = Some(smbios);
                        }
                    }
                    tag::ACPI_OLD => {
                        if let Ok(rsdp) = self.parse_acpi_rsdp(tag_ptr, tag_header.size, false) {
                            parsed.acpi_rsdp = Some(rsdp);
                        }
                    }
                    tag::ACPI_NEW => {
                        if let Ok(rsdp) = self.parse_acpi_rsdp(tag_ptr, tag_header.size, true) {
                            parsed.acpi_rsdp = Some(rsdp);
                        }
                    }
                    tag::EFI_MEMORY_MAP => {
                        if let Ok(map) = self.parse_efi_memory_map(tag_ptr, tag_header.size) {
                            parsed.efi_memory_map = Some(map);
                        }
                    }
                    tag::EFI_BOOT_SERVICES => {
                        parsed.efi_boot_services_not_terminated = true;
                    }
                    tag::EFI32_IMAGE_HANDLE => {
                        parsed.efi32_image_handle = self.parse_efi32_ptr(tag_ptr);
                    }
                    tag::EFI64_IMAGE_HANDLE => {
                        parsed.efi64_image_handle = self.parse_efi64_ptr(tag_ptr);
                    }
                    tag::IMAGE_LOAD_BASE => {
                        parsed.image_load_base = self.parse_image_load_base(tag_ptr);
                    }
                    _ => {
                        self.stats.unknown_tags.fetch_add(1, Ordering::SeqCst);
                    }
                }

                let next_offset = ((tag_header.size + 7) & !7) as usize;
                tag_ptr = tag_ptr.add(next_offset);
            }

            Ok(parsed)
        }
    }
}
