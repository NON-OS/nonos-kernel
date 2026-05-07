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

use x86_64::structures::paging::PageTableFlags;

use crate::elf::errors::ElfError;
use crate::elf::loader::image::LoadedSegment;
use crate::elf::types::ProgramHeader;
use crate::memory::addr::VirtAddr;

use super::populate_page::populate_page;
use super::pte_flags::pte_perms_from_phdr;

const PAGE: usize = 4096;

pub(in crate::elf::loader::core) fn load_segment(
    elf_data: &[u8],
    ph: &ProgramHeader,
    base_addr: VirtAddr,
    target_asid: u32,
) -> Result<LoadedSegment, ElfError> {
    use crate::sys::serial::println;
    let vaddr = base_addr + ph.p_vaddr;
    let seg_size = ph.p_memsz as usize;
    let file_size = ph.p_filesz as usize;
    let file_offset = ph.p_offset as usize;

    if file_size > 0 && file_offset + file_size > elf_data.len() {
        return Err(ElfError::SegmentDataOutOfBounds);
    }

    let perms = pte_perms_from_phdr(ph);
    let pages = (seg_size + PAGE - 1) / PAGE;

    let file_bytes = &elf_data[file_offset..file_offset + file_size];

    println(b"[ELF] seg start");
    for i in 0..pages {
        let page_off = i * PAGE;
        let page_va = vaddr + (i as u64 * PAGE as u64);
        if i == 0 {
            println(b"[ELF] first populate_page");
        }
        populate_page(target_asid, page_va, perms, file_bytes, page_off, file_size, seg_size)?;
        if i == 0 {
            println(b"[ELF] first populate_page done");
        }
    }
    println(b"[ELF] seg done");

    let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    if ph.is_writable() {
        flags |= PageTableFlags::WRITABLE;
    }
    if !ph.is_executable() {
        flags |= PageTableFlags::NO_EXECUTE;
    }

    Ok(LoadedSegment {
        vaddr,
        size: seg_size,
        flags,
        segment_type: ph.p_type,
    })
}
