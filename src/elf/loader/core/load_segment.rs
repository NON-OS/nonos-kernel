// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

use super::super::image::LoadedSegment;
use crate::elf::errors::ElfError;
use crate::elf::types::ProgramHeader;
use crate::memory::addr::VirtAddr;
use crate::memory::{frame_alloc, virtual_memory};
use core::ptr;
use x86_64::structures::paging::PageTableFlags;

pub(super) fn load_segment(
    elf_data: &[u8],
    ph: &ProgramHeader,
    base_addr: VirtAddr,
) -> Result<LoadedSegment, ElfError> {
    let (vaddr, size, file_size) =
        (base_addr + ph.p_vaddr, ph.p_memsz as usize, ph.p_filesz as usize);
    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if ph.is_writable() {
        flags |= PageTableFlags::WRITABLE;
    }
    if !ph.is_executable() {
        flags |= PageTableFlags::NO_EXECUTE;
    }
    let pages_needed = (size + 0xFFF) >> 12;
    for i in 0..pages_needed {
        if frame_alloc::allocate_frame().is_some() {
            let page_vaddr = vaddr + (i as u64 * 4096);
            virtual_memory::map_memory_range(
                page_vaddr,
                4096,
                flags_to_protection(flags),
                virtual_memory::VmType::File,
            )?;
        } else {
            return Err(ElfError::MemoryAllocationFailed);
        }
    }
    if file_size > 0 {
        let file_offset = ph.p_offset as usize;
        if file_offset + file_size > elf_data.len() {
            return Err(ElfError::SegmentDataOutOfBounds);
        }
        unsafe {
            ptr::copy_nonoverlapping(
                elf_data[file_offset..file_offset + file_size].as_ptr(),
                vaddr.as_mut_ptr::<u8>(),
                file_size,
            );
            if size > file_size {
                ptr::write_bytes(vaddr.as_mut_ptr::<u8>().add(file_size), 0, size - file_size);
            }
        }
    } else if size > 0 {
        unsafe {
            ptr::write_bytes(vaddr.as_mut_ptr::<u8>(), 0, size);
        }
    }
    Ok(LoadedSegment { vaddr, size, flags, segment_type: ph.p_type })
}

fn flags_to_protection(flags: PageTableFlags) -> virtual_memory::VmProtection {
    if flags.contains(PageTableFlags::WRITABLE) {
        if flags.contains(PageTableFlags::NO_EXECUTE) {
            virtual_memory::VmProtection::ReadWrite
        } else {
            virtual_memory::VmProtection::ReadWriteExecute
        }
    } else if flags.contains(PageTableFlags::NO_EXECUTE) {
        virtual_memory::VmProtection::Read
    } else {
        virtual_memory::VmProtection::ReadExecute
    }
}
