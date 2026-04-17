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
use super::types::*;

pub fn map_segment_pages(phdr: &Elf64ProgramHeader, vaddr: u64) -> Result<(), ElfError> {
    let page_offset = vaddr & 0xFFF;
    let aligned_vaddr = vaddr & !0xFFF;
    let aligned_filesz = phdr.p_filesz.checked_add(page_offset).and_then(|v| v.checked_add(0xFFF))
        .ok_or(ElfError::InvalidProgramHeader)? & !0xFFF;
    let aligned_memsz = phdr.p_memsz.checked_add(page_offset).and_then(|v| v.checked_add(0xFFF))
        .ok_or(ElfError::InvalidProgramHeader)? & !0xFFF;
    let file_pages = aligned_filesz as usize / 4096;
    let num_pages = aligned_memsz.max(aligned_filesz) as usize / 4096;

    for i in 0..num_pages {
        let page_addr = aligned_vaddr + (i as u64 * 4096);
        let is_file_backed = i < file_pages;
        let frame = crate::memory::phys::alloc(crate::memory::phys::AllocFlags::empty())
            .ok_or(ElfError::AllocationFailed)?;
        if !is_file_backed {
            unsafe {
                let virt = crate::memory::phys_to_virt(x86_64::PhysAddr::new(frame.0));
                core::ptr::write_bytes(virt.as_mut_ptr::<u8>(), 0, 4096);
            }
        }
        let writable = phdr.p_flags & PF_W != 0;
        let executable = phdr.p_flags & PF_X != 0;
        crate::memory::virt::map_page_4k(
            VirtAddr::new(page_addr), x86_64::PhysAddr::new(frame.0),
            writable, true, !executable,
        ).map_err(|_| ElfError::AllocationFailed)?;
    }
    Ok(())
}

pub fn copy_segment_data(data: &[u8], phdr: &Elf64ProgramHeader, vaddr: u64) -> Result<(), ElfError> {
    if phdr.p_filesz > 0 {
        let file_offset = phdr.p_offset as usize;
        let file_end = file_offset.checked_add(phdr.p_filesz as usize).ok_or(ElfError::InvalidProgramHeader)?;
        if file_end > data.len() { return Err(ElfError::InvalidProgramHeader); }
        let src = &data[file_offset..file_end];
        let dst = vaddr as *mut u8;
        unsafe { core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len()); }
    }
    if phdr.p_memsz > phdr.p_filesz {
        let bss_start = vaddr + phdr.p_filesz;
        let bss_size = phdr.p_memsz - phdr.p_filesz;
        unsafe { core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size as usize); }
    }
    Ok(())
}
