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
use x86_64::PhysAddr;

use super::super::types::{FramebufferInfo, MemoryMapEntry, ModuleInfo, MultibootError};
use super::tags::{FramebufferTag, MemoryMapTag, ModuleTag};

/// Parse memory map tag
///
/// # Safety
///
/// tag_ptr must point to valid memory of at least tag_size bytes.
pub unsafe fn parse_memory_map(
    tag_ptr: *const u8,
    tag_size: u32,
) -> Result<Vec<MemoryMapEntry>, MultibootError> {
    const HEADER_SIZE: u32 = 16;
    const MIN_ENTRY_SIZE: u32 = 24;
    const MAX_ENTRIES: u32 = 1024;

    if tag_size < HEADER_SIZE {
        return Err(MultibootError::MemoryMapError);
    }

    // SAFETY: Caller guarantees tag_ptr is valid for tag_size bytes
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

    // SAFETY: Bounds validated above
    let entry_ptr = unsafe { tag_ptr.add(HEADER_SIZE as usize) as *const MemoryMapEntry };
    for i in 0..num_entries {
        // SAFETY: i < num_entries, validated above
        entries.push(unsafe { *entry_ptr.add(i as usize) });
    }

    Ok(entries)
}

/// Parse framebuffer tag
///
/// # Safety
///
/// tag_ptr must point to valid memory of at least tag_size bytes.
pub unsafe fn parse_framebuffer_info(
    tag_ptr: *const u8,
    tag_size: u32,
) -> Result<FramebufferInfo, MultibootError> {
    const MIN_TAG_SIZE: u32 = 31;

    if tag_size < MIN_TAG_SIZE {
        return Err(MultibootError::FramebufferError);
    }

    // SAFETY: Caller guarantees tag_ptr is valid for tag_size bytes
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

/// Parse module tag
///
/// # Safety
///
/// tag_ptr must point to valid memory of at least tag_size bytes.
pub unsafe fn parse_module_info(
    tag_ptr: *const u8,
    tag_size: u32,
) -> Result<ModuleInfo, MultibootError> {
    const HEADER_SIZE: usize = 16;
    const MAX_CMDLINE_LEN: usize = 4096;

    if (tag_size as usize) < HEADER_SIZE {
        return Err(MultibootError::ModuleError);
    }

    // SAFETY: Caller guarantees tag_ptr is valid for tag_size bytes
    let tag = unsafe { &*(tag_ptr as *const ModuleTag) };

    if tag.mod_end < tag.mod_start {
        return Err(MultibootError::ModuleError);
    }

    let cmdline = if (tag_size as usize) > HEADER_SIZE {
        // SAFETY: Header size validated above
        let cmdline_ptr = unsafe { tag_ptr.add(HEADER_SIZE) };
        let max_len = ((tag_size as usize).saturating_sub(HEADER_SIZE)).min(MAX_CMDLINE_LEN);

        let mut len = 0;
        // SAFETY: Bounds checked by tag_size validation
        while len < max_len && unsafe { *cmdline_ptr.add(len) } != 0 {
            len += 1;
        }

        if len > 0 {
            // SAFETY: len validated above
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
