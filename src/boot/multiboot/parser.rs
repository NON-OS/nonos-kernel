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
use core::slice;
use x86_64::{PhysAddr, VirtAddr};
use super::types::{
    FramebufferInfo, MemoryMapEntry, ModuleInfo, Multiboot2Info, MultibootError, MultibootInfo,
};

mod tag_type {
    pub(super) const END: u32 = 0;
    pub(super) const CMDLINE: u32 = 1;
    pub(super) const BOOTLOADER_NAME: u32 = 2;
    pub(super) const MODULE: u32 = 3;
    pub(super) const BASIC_MEMINFO: u32 = 4;
    pub(super) const BOOTDEV: u32 = 5;
    pub(super) const MMAP: u32 = 6;
    pub(super) const VBE: u32 = 7;
    pub(super) const FRAMEBUFFER: u32 = 8;
    pub(super) const ELF_SECTIONS: u32 = 9;
    pub(super) const APM: u32 = 10;
}

#[repr(C)]
struct TagHeader {
    tag_type: u32,
    size: u32,
}
/// # Safety {
/// info_addr must point to a valid Multiboot2 information structure
/// the memory must remain valid for the lifetime of returned data
/// }
pub unsafe fn parse_multiboot_info(info_addr: VirtAddr) -> Result<MultibootInfo, MultibootError> {
    const MIN_INFO_SIZE: u32 = 8;
    const MAX_INFO_SIZE: u32 = 16 * 1024 * 1024; // 16MB sanity limit
    const MIN_TAG_SIZE: u32 = 8;
    // # SAFETY: Caller guarantees info_addr points to valid Multiboot2Info
    let info = unsafe { &*info_addr.as_ptr::<Multiboot2Info>() };
    if info.total_size < MIN_INFO_SIZE {
        return Err(MultibootError::InvalidSize);
    }

    if info.total_size > MAX_INFO_SIZE {
        return Err(MultibootError::InvalidSize);
    }

    let mut memory_map = None;
    let mut framebuffer_info = None;
    let mut module_info = None;
    let info_start = info_addr.as_u64();
    let info_end = info_start
        .checked_add(info.total_size as u64)
        .ok_or(MultibootError::InvalidSize)?;

    let mut tag_ptr = (info_addr + 8u64).as_ptr::<u8>();
    let end_ptr = (info_addr + info.total_size as u64).as_ptr::<u8>();
    while tag_ptr < end_ptr {
        // # SAFETY: Bounds checked above
        let tag_header = unsafe { &*(tag_ptr as *const TagHeader) };
        if tag_header.size < MIN_TAG_SIZE {
            return Err(MultibootError::InvalidTag { tag_type: tag_header.tag_type });
        }

        let tag_end = (tag_ptr as u64)
            .checked_add(tag_header.size as u64)
            .ok_or(MultibootError::InvalidTag { tag_type: tag_header.tag_type })?;

        if tag_end > info_end {
            return Err(MultibootError::InvalidTag { tag_type: tag_header.tag_type });
        }

        if tag_header.tag_type == tag_type::END && tag_header.size == 8 {
            break;
        }

        // # SAFETY: Tag bounds validated above
        match tag_header.tag_type {
            tag_type::MMAP => {
                memory_map = Some(unsafe { parse_memory_map(tag_ptr, tag_header.size)? });
            }
            tag_type::FRAMEBUFFER => {
                framebuffer_info = Some(unsafe { parse_framebuffer_info(tag_ptr, tag_header.size)? });
            }
            tag_type::MODULE => {
                module_info = Some(unsafe { parse_module_info(tag_ptr, tag_header.size)? });
            }
            _ => {} // Skip unknown/unused tags
        }

        let next_offset = (tag_header.size + 7) & !7;
        // # SAFETY: Offset validated, won't exceed end_ptr
        tag_ptr = unsafe { tag_ptr.add(next_offset as usize) };
    }

    Ok(MultibootInfo {
        memory_map: memory_map.unwrap_or_default(),
        framebuffer_info,
        module_info,
    })
}

/// # Safety:  tag_ptr must point to valid memory of at least tag_size bytes.
unsafe fn parse_memory_map(tag_ptr: *const u8, tag_size: u32) -> Result<Vec<MemoryMapEntry>, MultibootError> {
    const HEADER_SIZE: u32 = 16;
    const MIN_ENTRY_SIZE: u32 = 24;
    const MAX_ENTRIES: u32 = 1024; // Sanity limit
    #[repr(C)]
    struct MemoryMapTag {
        tag_type: u32,
        size: u32,
        entry_size: u32,
        entry_version: u32,
    }

    if tag_size < HEADER_SIZE {
        return Err(MultibootError::MemoryMapError);
    }

    // # SAFETY: Caller guarantees tag_ptr is valid for tag_size bytes
    let tag = unsafe { &*(tag_ptr as *const MemoryMapTag) };
    if tag.entry_size < MIN_ENTRY_SIZE {
        return Err(MultibootError::MemoryMapError);
    }

    let entries_size = tag_size.saturating_sub(HEADER_SIZE);
    let num_entries = entries_size / tag.entry_size;
    if num_entries > MAX_ENTRIES {
        return Err(MultibootError::MemoryMapError);
    }

    let mut entries = Vec::with_capacity(num_entries as usize);
    // # SAFETY: Bounds validated above
    let entry_ptr = unsafe { tag_ptr.add(HEADER_SIZE as usize) as *const MemoryMapEntry };
    for i in 0..num_entries {
        // # SAFETY: i < num_entries, validated above
        entries.push(unsafe { *entry_ptr.add(i as usize) });
    }

    Ok(entries)
}

/// # Safety: tag_ptr must point to valid memory of at least tag_size bytes.
unsafe fn parse_framebuffer_info(tag_ptr: *const u8, tag_size: u32) -> Result<FramebufferInfo, MultibootError> {
    const MIN_TAG_SIZE: u32 = 31; // Minimum size for framebuffer tag
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

    if tag_size < MIN_TAG_SIZE {
        return Err(MultibootError::FramebufferError);
    }

    // # SAFETY: Caller guarantees tag_ptr is valid for tag_size bytes
    let tag = unsafe { &*(tag_ptr as *const FramebufferTag) };

    if tag.framebuffer_width == 0 || tag.framebuffer_height == 0 {
        return Err(MultibootError::FramebufferError);
    }

    if tag.framebuffer_pitch == 0 || tag.framebuffer_bpp == 0 {
        return Err(MultibootError::FramebufferError);
    }

    const MAX_PHYS_ADDR: u64 = 0x0000_FFFF_FFFF_FFFF;
    if tag.framebuffer_addr > MAX_PHYS_ADDR {
        return Err(MultibootError::FramebufferError);
    }

    Ok(FramebufferInfo {
        addr: PhysAddr::new(tag.framebuffer_addr),
        width: tag.framebuffer_width,
        height: tag.framebuffer_height,
        pitch: tag.framebuffer_pitch,
        bpp: tag.framebuffer_bpp,
        framebuffer_type: tag.framebuffer_type,
    })
}
/// # Safety: tag_ptr must point to valid memory of at least tag_size bytes.
unsafe fn parse_module_info(tag_ptr: *const u8, tag_size: u32) -> Result<ModuleInfo, MultibootError> {
    const HEADER_SIZE: usize = 16;
    const MAX_CMDLINE_LEN: usize = 4096;
    #[repr(C)]
    struct ModuleTag {
        tag_type: u32,
        size: u32,
        mod_start: u32,
        mod_end: u32,
    }

    if (tag_size as usize) < HEADER_SIZE {
        return Err(MultibootError::ModuleError);
    }

    // # SAFETY: Caller guarantees tag_ptr is valid for tag_size bytes
    let tag = unsafe { &*(tag_ptr as *const ModuleTag) };
    if tag.mod_end < tag.mod_start {
        return Err(MultibootError::ModuleError);
    }

    let cmdline = if (tag_size as usize) > HEADER_SIZE {
        // SAFETY: Header size validated above
        let cmdline_ptr = unsafe { tag_ptr.add(HEADER_SIZE) };
        let max_len = ((tag_size as usize).saturating_sub(HEADER_SIZE)).min(MAX_CMDLINE_LEN);
        let mut len = 0;
        // # SAFETY: Bounds checked by tag_size validation
        while len < max_len && unsafe { *cmdline_ptr.add(len) } != 0 {
            len += 1;
        }

        if len > 0 {
            // # SAFETY: len validated above
            let bytes = unsafe { slice::from_raw_parts(cmdline_ptr, len) };
            core::str::from_utf8(bytes).ok()
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
