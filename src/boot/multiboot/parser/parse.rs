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

use x86_64::VirtAddr;

use super::super::types::{Multiboot2Info, MultibootError, MultibootInfo};
use super::helpers::{parse_framebuffer_info, parse_memory_map, parse_module_info};
use super::tags::{tag_type, TagHeader};

pub unsafe fn parse_multiboot_info(info_addr: VirtAddr) -> Result<MultibootInfo, MultibootError> {
    const MIN_INFO_SIZE: u32 = 8;
    const MAX_INFO_SIZE: u32 = 16 * 1024 * 1024;
    const MIN_TAG_SIZE: u32 = 8;

    // SAFETY: Caller guarantees info_addr points to valid Multiboot2Info
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
        // SAFETY: Bounds checked above
        let tag_header = unsafe { &*(tag_ptr as *const TagHeader) };

        if tag_header.size < MIN_TAG_SIZE {
            return Err(MultibootError::InvalidTag {
                tag_type: tag_header.tag_type,
            });
        }

        let tag_end = (tag_ptr as u64)
            .checked_add(tag_header.size as u64)
            .ok_or(MultibootError::InvalidTag {
                tag_type: tag_header.tag_type,
            })?;

        if tag_end > info_end {
            return Err(MultibootError::InvalidTag {
                tag_type: tag_header.tag_type,
            });
        }

        if tag_header.tag_type == tag_type::END && tag_header.size == 8 {
            break;
        }

        // SAFETY: Tag bounds validated above
        match tag_header.tag_type {
            tag_type::MMAP => {
                memory_map = Some(unsafe { parse_memory_map(tag_ptr, tag_header.size)? });
            }
            tag_type::FRAMEBUFFER => {
                framebuffer_info =
                    Some(unsafe { parse_framebuffer_info(tag_ptr, tag_header.size)? });
            }
            tag_type::MODULE => {
                module_info = Some(unsafe { parse_module_info(tag_ptr, tag_header.size)? });
            }
            _ => {}
        }

        let next_offset = (tag_header.size + 7) & !7;
        // SAFETY: Offset validated, won't exceed end_ptr
        tag_ptr = unsafe { tag_ptr.add(next_offset as usize) };
    }

    Ok(MultibootInfo {
        memory_map: memory_map.unwrap_or_default(),
        framebuffer_info,
        module_info,
    })
}
