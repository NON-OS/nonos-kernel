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
use core::slice;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::RwLock;
use x86_64::{PhysAddr, VirtAddr};

use super::constants::{tag, MULTIBOOT2_BOOTLOADER_MAGIC};
use super::error::MultibootError;
use super::framebuffer::{ColorInfo, FramebufferInfo, FramebufferType};
use super::header::{Multiboot2Info, TagHeader};
use super::info::ParsedMultibootInfo;
use super::memory_map::{EfiMemoryDescriptor, MemoryMapEntry};
use super::modules::{
    AcpiRsdp, ApmTable, BasicMemInfo, BiosBootDevice, ElfSection, ElfSections, ModuleInfo,
    SmbiosInfo, VbeInfo,
};
use super::platform::{detect_platform, Platform};
use super::stats::MultibootStats;

pub static MULTIBOOT_MANAGER: MultibootManager = MultibootManager::new();

pub struct MultibootManager {
    initialized: AtomicBool,
    bootloader_magic: AtomicU64,
    parsed_info: RwLock<Option<ParsedMultibootInfo>>,
    platform: RwLock<Platform>,
    stats: MultibootStats,
}

impl MultibootManager {
    pub const fn new() -> Self {
        Self {
            initialized: AtomicBool::new(false),
            bootloader_magic: AtomicU64::new(0),
            parsed_info: RwLock::new(None),
            platform: RwLock::new(Platform::BareMetal),
            stats: MultibootStats::new(),
        }
    }

    /// # Safety
    /// The info_addr must point to a valid Multiboot2 information structure.
    pub unsafe fn initialize(
        &self,
        magic: u32,
        info_addr: VirtAddr,
    ) -> Result<(), MultibootError> {
        unsafe {
            if self.initialized.load(Ordering::SeqCst) {
                return Err(MultibootError::AlreadyInitialized);
            }

            if magic != MULTIBOOT2_BOOTLOADER_MAGIC {
                return Err(MultibootError::InvalidMagic {
                    expected: MULTIBOOT2_BOOTLOADER_MAGIC,
                    found: magic,
                });
            }

            self.bootloader_magic.store(magic as u64, Ordering::SeqCst);

            let parsed = self.parse_info(info_addr)?;

            self.stats
                .total_available_memory
                .store(parsed.total_available_memory(), Ordering::SeqCst);
            self.stats
                .total_reserved_memory
                .store(parsed.total_reserved_memory(), Ordering::SeqCst);

            *self.parsed_info.write() = Some(parsed);

            let platform = detect_platform();
            *self.platform.write() = platform;

            self.initialized.store(true, Ordering::SeqCst);

            crate::log::info!(
                "Multiboot2 initialized: {} available, {} reserved, platform: {}",
                format_bytes(self.stats.total_available_memory.load(Ordering::SeqCst)),
                format_bytes(self.stats.total_reserved_memory.load(Ordering::SeqCst)),
                platform.name()
            );

            Ok(())
        }
    }

    unsafe fn parse_info(
        &self,
        info_addr: VirtAddr,
    ) -> Result<ParsedMultibootInfo, MultibootError> {
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

    unsafe fn parse_string_tag(&self, tag_ptr: *const u8, size: u32) -> Option<String> {
        unsafe {
            if size <= 8 {
                return None;
            }

            let string_ptr = tag_ptr.add(8);
            let max_len = (size - 8) as usize;
            let mut len = 0;

            while len < max_len {
                if *string_ptr.add(len) == 0 {
                    break;
                }
                len += 1;
            }

            if len == 0 {
                return None;
            }

            let slice = slice::from_raw_parts(string_ptr, len);
            core::str::from_utf8(slice).ok().map(String::from)
        }
    }

    unsafe fn parse_module(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<ModuleInfo, MultibootError> {
        unsafe {
            #[repr(C)]
            struct ModuleTag {
                tag_type: u32,
                size: u32,
                mod_start: u32,
                mod_end: u32,
            }

            let tag = &*(tag_ptr as *const ModuleTag);

            if tag.mod_end < tag.mod_start {
                return Err(MultibootError::ModuleError {
                    reason: "Invalid module bounds",
                });
            }

            let cmdline = if size > 16 {
                let cmdline_ptr = tag_ptr.add(16);
                let max_len = (size - 16) as usize;
                let mut len = 0;
                while len < max_len && *cmdline_ptr.add(len) != 0 {
                    len += 1;
                }
                if len > 0 {
                    let slice = slice::from_raw_parts(cmdline_ptr, len);
                    core::str::from_utf8(slice).ok().map(String::from)
                } else {
                    None
                }
            } else {
                None
            };

            Ok(ModuleInfo {
                start: PhysAddr::new(tag.mod_start as u64),
                end: PhysAddr::new(tag.mod_end as u64),
                cmdline,
            })
        }
    }

    unsafe fn parse_basic_meminfo(&self, tag_ptr: *const u8) -> Option<BasicMemInfo> {
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

    unsafe fn parse_boot_device(&self, tag_ptr: *const u8) -> Option<BiosBootDevice> {
        unsafe {
            #[repr(C)]
            struct BootDeviceTag {
                tag_type: u32,
                size: u32,
                biosdev: u32,
                partition: u32,
                sub_partition: u32,
            }

            let tag = &*(tag_ptr as *const BootDeviceTag);
            Some(BiosBootDevice {
                bios_dev: tag.biosdev,
                partition: tag.partition,
                sub_partition: tag.sub_partition,
            })
        }
    }

    unsafe fn parse_memory_map(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<Vec<MemoryMapEntry>, MultibootError> {
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

    unsafe fn parse_vbe_info(&self, tag_ptr: *const u8, size: u32) -> Option<VbeInfo> {
        unsafe {
            if size < 8 + 8 + 512 + 256 {
                return None;
            }

            #[repr(C)]
            struct VbeTag {
                tag_type: u32,
                size: u32,
                vbe_mode: u16,
                vbe_interface_seg: u16,
                vbe_interface_off: u16,
                vbe_interface_len: u16,
                vbe_control_info: [u8; 512],
                vbe_mode_info: [u8; 256],
            }

            let tag = &*(tag_ptr as *const VbeTag);
            Some(VbeInfo {
                mode: tag.vbe_mode,
                interface_seg: tag.vbe_interface_seg,
                interface_off: tag.vbe_interface_off,
                interface_len: tag.vbe_interface_len,
                control_info: tag.vbe_control_info,
                mode_info: tag.vbe_mode_info,
            })
        }
    }

    unsafe fn parse_framebuffer(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<FramebufferInfo, MultibootError> {
        unsafe {
            #[repr(C)]
            struct FramebufferTag {
                tag_type: u32,
                size: u32,
                framebuffer_addr: u64,
                framebuffer_pitch: u32,
                framebuffer_width: u32,
                framebuffer_height: u32,
                framebuffer_bpp: u8,
                framebuffer_type: u8,
                reserved: u8,
            }

            if size < core::mem::size_of::<FramebufferTag>() as u32 {
                return Err(MultibootError::FramebufferError {
                    reason: "Tag too small",
                });
            }

            let tag = &*(tag_ptr as *const FramebufferTag);

            let fb_type = FramebufferType::from(tag.framebuffer_type);

            let color_info = if fb_type == FramebufferType::DirectRgb && size >= 31 {
                let color_ptr = tag_ptr.add(27);
                Some(ColorInfo {
                    red_position: *color_ptr,
                    red_mask_size: *color_ptr.add(1),
                    green_position: *color_ptr.add(2),
                    green_mask_size: *color_ptr.add(3),
                    blue_position: *color_ptr.add(4),
                    blue_mask_size: *color_ptr.add(5),
                })
            } else {
                None
            };

            Ok(FramebufferInfo {
                addr: PhysAddr::new(tag.framebuffer_addr),
                pitch: tag.framebuffer_pitch,
                width: tag.framebuffer_width,
                height: tag.framebuffer_height,
                bpp: tag.framebuffer_bpp,
                framebuffer_type: fb_type,
                color_info,
            })
        }
    }

    unsafe fn parse_elf_sections(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<ElfSections, MultibootError> {
        unsafe {
            #[repr(C)]
            struct ElfSectionsTag {
                tag_type: u32,
                size: u32,
                num: u32,
                entsize: u32,
                shndx: u32,
            }

            if size < core::mem::size_of::<ElfSectionsTag>() as u32 {
                return Err(MultibootError::ElfSectionError {
                    reason: "Tag too small",
                });
            }

            let tag = &*(tag_ptr as *const ElfSectionsTag);

            let mut sections = Vec::with_capacity(tag.num as usize);
            let section_data_ptr = tag_ptr.add(20);

            for i in 0..tag.num {
                let section_ptr = section_data_ptr.add((i * tag.entsize) as usize);

                #[repr(C)]
                struct Elf64Shdr {
                    sh_name: u32,
                    sh_type: u32,
                    sh_flags: u64,
                    sh_addr: u64,
                    sh_offset: u64,
                    sh_size: u64,
                    sh_link: u32,
                    sh_info: u32,
                    sh_addralign: u64,
                    sh_entsize: u64,
                }

                if tag.entsize >= core::mem::size_of::<Elf64Shdr>() as u32 {
                    let shdr = &*(section_ptr as *const Elf64Shdr);
                    sections.push(ElfSection {
                        name_index: shdr.sh_name,
                        section_type: shdr.sh_type,
                        flags: shdr.sh_flags,
                        addr: shdr.sh_addr,
                        offset: shdr.sh_offset,
                        size: shdr.sh_size,
                        link: shdr.sh_link,
                        info: shdr.sh_info,
                        addralign: shdr.sh_addralign,
                        entsize: shdr.sh_entsize,
                    });
                }
            }

            Ok(ElfSections {
                num: tag.num,
                entsize: tag.entsize,
                shndx: tag.shndx,
                sections,
            })
        }
    }

    unsafe fn parse_apm(&self, tag_ptr: *const u8) -> Option<ApmTable> {
        unsafe {
            #[repr(C)]
            struct ApmTag {
                tag_type: u32,
                size: u32,
                version: u16,
                cseg: u16,
                offset: u32,
                cseg_16: u16,
                dseg: u16,
                flags: u16,
                cseg_len: u16,
                cseg_16_len: u16,
                dseg_len: u16,
            }

            let tag = &*(tag_ptr as *const ApmTag);
            Some(ApmTable {
                version: tag.version,
                cseg: tag.cseg,
                offset: tag.offset,
                cseg_16: tag.cseg_16,
                dseg: tag.dseg,
                flags: tag.flags,
                cseg_len: tag.cseg_len,
                cseg_16_len: tag.cseg_16_len,
                dseg_len: tag.dseg_len,
            })
        }
    }

    unsafe fn parse_acpi_rsdp(
        &self,
        tag_ptr: *const u8,
        size: u32,
        is_new: bool,
    ) -> Result<AcpiRsdp, MultibootError> {
        unsafe {
            let rsdp_ptr = tag_ptr.add(8);
            let rsdp_size = size.saturating_sub(8) as usize;

            if rsdp_size < 20 {
                return Err(MultibootError::AcpiError {
                    reason: "RSDP too small",
                });
            }

            let mut signature = [0u8; 8];
            signature.copy_from_slice(slice::from_raw_parts(rsdp_ptr, 8));

            if &signature != b"RSD PTR " {
                return Err(MultibootError::AcpiError {
                    reason: "Invalid RSDP signature",
                });
            }

            let mut oem_id = [0u8; 6];
            oem_id.copy_from_slice(slice::from_raw_parts(rsdp_ptr.add(9), 6));

            let checksum = *rsdp_ptr.add(8);
            let revision = *rsdp_ptr.add(15);
            let rsdt_address = *(rsdp_ptr.add(16) as *const u32);

            let (length, xsdt_address, extended_checksum) = if is_new && rsdp_size >= 36 {
                let length = *(rsdp_ptr.add(20) as *const u32);
                let xsdt_address = *(rsdp_ptr.add(24) as *const u64);
                let extended_checksum = *rsdp_ptr.add(32);
                (Some(length), Some(xsdt_address), Some(extended_checksum))
            } else {
                (None, None, None)
            };

            Ok(AcpiRsdp {
                signature,
                checksum,
                oem_id,
                revision,
                rsdt_address,
                length,
                xsdt_address,
                extended_checksum,
            })
        }
    }

    unsafe fn parse_smbios(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<SmbiosInfo, MultibootError> {
        unsafe {
            if size < 16 {
                return Err(MultibootError::SmbiosError {
                    reason: "Tag too small",
                });
            }

            #[repr(C)]
            struct SmbiosTag {
                tag_type: u32,
                size: u32,
                major: u8,
                minor: u8,
                reserved: [u8; 6],
            }

            let tag = &*(tag_ptr as *const SmbiosTag);

            let table_ptr = tag_ptr.add(16);
            let table_size = size.saturating_sub(16);

            Ok(SmbiosInfo {
                major_version: tag.major,
                minor_version: tag.minor,
                table_address: PhysAddr::new(table_ptr as u64),
                table_length: table_size,
            })
        }
    }

    unsafe fn parse_efi32_ptr(&self, tag_ptr: *const u8) -> Option<u32> {
        unsafe {
            let ptr = *(tag_ptr.add(8) as *const u32);
            if ptr != 0 {
                Some(ptr)
            } else {
                None
            }
        }
    }

    unsafe fn parse_efi64_ptr(&self, tag_ptr: *const u8) -> Option<u64> {
        unsafe {
            let ptr = *(tag_ptr.add(8) as *const u64);
            if ptr != 0 {
                Some(ptr)
            } else {
                None
            }
        }
    }

    unsafe fn parse_efi_memory_map(
        &self,
        tag_ptr: *const u8,
        size: u32,
    ) -> Result<Vec<EfiMemoryDescriptor>, MultibootError> {
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

    unsafe fn parse_image_load_base(&self, tag_ptr: *const u8) -> Option<PhysAddr> {
        unsafe {
            let addr = *(tag_ptr.add(8) as *const u32);
            Some(PhysAddr::new(addr as u64))
        }
    }

    pub fn is_initialized(&self) -> bool {
        self.initialized.load(Ordering::SeqCst)
    }

    pub fn platform(&self) -> Platform {
        *self.platform.read()
    }

    pub fn set_platform(&self, platform: Platform) {
        *self.platform.write() = platform;
    }

    pub fn info(&self) -> Option<ParsedMultibootInfo> {
        self.parsed_info.read().clone()
    }

    pub fn stats(&self) -> &MultibootStats {
        &self.stats
    }

    pub fn cmdline(&self) -> Option<String> {
        self.parsed_info
            .read()
            .as_ref()
            .and_then(|i| i.cmdline.clone())
    }

    pub fn bootloader_name(&self) -> Option<String> {
        self.parsed_info
            .read()
            .as_ref()
            .and_then(|i| i.bootloader_name.clone())
    }

    pub fn memory_map(&self) -> Vec<MemoryMapEntry> {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.memory_map.clone())
            .unwrap_or_default()
    }

    pub fn framebuffer(&self) -> Option<FramebufferInfo> {
        self.parsed_info
            .read()
            .as_ref()
            .and_then(|i| i.framebuffer.clone())
    }

    pub fn modules(&self) -> Vec<ModuleInfo> {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.modules.clone())
            .unwrap_or_default()
    }

    pub fn acpi_rsdp(&self) -> Option<AcpiRsdp> {
        self.parsed_info
            .read()
            .as_ref()
            .and_then(|i| i.acpi_rsdp.clone())
    }

    pub fn is_efi_boot(&self) -> bool {
        self.parsed_info
            .read()
            .as_ref()
            .map(|i| i.is_efi_boot())
            .unwrap_or(false)
    }
}

fn format_bytes(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;

    if bytes >= GB {
        alloc::format!("{} GB", bytes / GB)
    } else if bytes >= MB {
        alloc::format!("{} MB", bytes / MB)
    } else if bytes >= KB {
        alloc::format!("{} KB", bytes / KB)
    } else {
        alloc::format!("{} B", bytes)
    }
}
