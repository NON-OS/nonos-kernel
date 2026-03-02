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

use alloc::string::String;
use alloc::vec::Vec;
use x86_64::VirtAddr;

use super::types::*;
use super::parser::{parse_header, get_program_headers};

const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

fn validate_user_address(addr: u64, size: u64) -> Result<(), ElfError> {
    if addr >= USER_SPACE_END {
        return Err(ElfError::InvalidAddress);
    }

    if let Some(end) = addr.checked_add(size) {
        if end > USER_SPACE_END {
            return Err(ElfError::InvalidAddress);
        }
    } else {
        return Err(ElfError::InvalidAddress);
    }

    Ok(())
}

fn check_wx(flags: u32) -> Result<(), ElfError> {
    if (flags & PF_W != 0) && (flags & PF_X != 0) {
        return Err(ElfError::WXViolation);
    }
    Ok(())
}

pub fn load_elf(data: &[u8], base_addr: u64) -> Result<LoadedElf, ElfError> {
    let header = parse_header(data)?;

    let phdrs = get_program_headers(data, header)?;

    let is_pie = header.e_type == ET_DYN;
    let actual_base = if is_pie { base_addr } else { 0 };

    let mut loaded = LoadedElf {
        entry: header.e_entry + actual_base,
        base_addr: actual_base,
        phdr_addr: 0,
        phnum: header.e_phnum,
        phentsize: header.e_phentsize,
        segments: Vec::new(),
        interp: None,
        exec_stack: false,
        min_addr: u64::MAX,
        max_addr: 0,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };

    for phdr in phdrs {
        if phdr.p_type != PT_LOAD {
            continue;
        }

        let vaddr = phdr.p_vaddr + actual_base;

        validate_user_address(vaddr, phdr.p_memsz)?;

        if phdr.p_flags & PF_W != 0 && phdr.p_flags & PF_X != 0 {
            crate::log::log_warning!("[ELF] W+X segment at 0x{:016X}", vaddr);
        }

        if phdr.p_align > 1 && phdr.p_vaddr % phdr.p_align != phdr.p_offset % phdr.p_align {
            return Err(ElfError::InvalidAlignment);
        }
    }

    for phdr in phdrs {
        match phdr.p_type {
            PT_LOAD => {
                let vaddr = phdr.p_vaddr + actual_base;

                let page_offset = vaddr & 0xFFF;
                let aligned_vaddr = vaddr & !0xFFF;
                let _aligned_filesz = (phdr.p_filesz + page_offset + 0xFFF) & !0xFFF;
                let aligned_memsz = (phdr.p_memsz + page_offset + 0xFFF) & !0xFFF;

                let num_pages = aligned_memsz as usize / 4096;
                for i in 0..num_pages {
                    let page_addr = aligned_vaddr + (i as u64 * 4096);

                    let frame = crate::memory::phys::alloc(crate::memory::phys::AllocFlags::empty())
                        .ok_or(ElfError::AllocationFailed)?;

                    let writable = phdr.p_flags & PF_W != 0;
                    let executable = phdr.p_flags & PF_X != 0;

                    crate::memory::virt::map_page_4k(
                        VirtAddr::new(page_addr),
                        x86_64::PhysAddr::new(frame.0),
                        writable,
                        true,
                        !executable,
                    ).map_err(|_| ElfError::AllocationFailed)?;
                }

                if phdr.p_filesz > 0 {
                    let file_offset = phdr.p_offset as usize;
                    let file_end = file_offset + phdr.p_filesz as usize;

                    if file_end > data.len() {
                        return Err(ElfError::InvalidProgramHeader);
                    }

                    let src = &data[file_offset..file_end];
                    let dst = vaddr as *mut u8;

                    // SAFETY: The destination address (vaddr) was validated to be in
                    // user space and the required pages were mapped above. The source
                    // slice bounds were verified against data.len(). The regions cannot
                    // overlap since src is from the kernel's ELF buffer and dst is in
                    // user-mapped memory.
                    unsafe {
                        core::ptr::copy_nonoverlapping(src.as_ptr(), dst, src.len());
                    }
                }

                if phdr.p_memsz > phdr.p_filesz {
                    let bss_start = vaddr + phdr.p_filesz;
                    let bss_size = phdr.p_memsz - phdr.p_filesz;

                    // SAFETY: The BSS region (bss_start to bss_start + bss_size) was
                    // validated to be in user space (part of the p_memsz region) and
                    // the pages were mapped above. write_bytes zeroes the BSS section
                    // which is required by the ELF ABI.
                    unsafe {
                        core::ptr::write_bytes(bss_start as *mut u8, 0, bss_size as usize);
                    }
                }

                loaded.segments.push(LoadedSegment {
                    vaddr,
                    memsz: phdr.p_memsz,
                    flags: phdr.p_flags,
                    file_offset: phdr.p_offset,
                    filesz: phdr.p_filesz,
                });

                loaded.min_addr = loaded.min_addr.min(vaddr);
                loaded.max_addr = loaded.max_addr.max(vaddr + phdr.p_memsz);
            }

            PT_INTERP => {
                let interp_offset = phdr.p_offset as usize;
                let interp_size = phdr.p_filesz as usize;

                if interp_offset + interp_size > data.len() {
                    return Err(ElfError::InvalidProgramHeader);
                }

                let interp_bytes = &data[interp_offset..interp_offset + interp_size];
                let interp_len = interp_bytes.iter().position(|&c| c == 0).unwrap_or(interp_size);
                let interp_str = core::str::from_utf8(&interp_bytes[..interp_len])
                    .map_err(|_| ElfError::InvalidProgramHeader)?;

                loaded.interp = Some(String::from(interp_str));
            }

            PT_PHDR => {
                loaded.phdr_addr = phdr.p_vaddr + actual_base;
            }

            PT_GNU_STACK => {
                loaded.exec_stack = phdr.p_flags & PF_X != 0;
                if loaded.exec_stack {
                    crate::log::log_warning!("[ELF] Executable stack requested");
                }
            }

            PT_TLS => {
                loaded.tls_addr = phdr.p_vaddr + actual_base;
                loaded.tls_size = phdr.p_memsz;
                loaded.tls_align = phdr.p_align;
            }

            _ => {}
        }
    }

    if loaded.phdr_addr == 0 && header.e_phoff != 0 {
        for seg in &loaded.segments {
            if seg.file_offset <= header.e_phoff
                && seg.file_offset + seg.filesz >= header.e_phoff + (header.e_phnum as u64 * header.e_phentsize as u64)
            {
                loaded.phdr_addr = seg.vaddr + (header.e_phoff - seg.file_offset);
                break;
            }
        }
    }

    crate::log::info!(
        "[ELF] Loaded binary: entry=0x{:016X}, segments={}, range=0x{:X}-0x{:X}",
        loaded.entry,
        loaded.segments.len(),
        loaded.min_addr,
        loaded.max_addr
    );

    Ok(loaded)
}

pub fn build_auxv(loaded: &LoadedElf, exec_name_addr: u64, random_addr: u64) -> Vec<(u64, u64)> {
    let mut auxv = Vec::new();

    auxv.push((AT_PHDR, loaded.phdr_addr));
    auxv.push((AT_PHENT, loaded.phentsize as u64));
    auxv.push((AT_PHNUM, loaded.phnum as u64));
    auxv.push((AT_PAGESZ, 4096));
    auxv.push((AT_BASE, loaded.base_addr));
    auxv.push((AT_ENTRY, loaded.entry));
    auxv.push((AT_UID, 0));
    auxv.push((AT_EUID, 0));
    auxv.push((AT_GID, 0));
    auxv.push((AT_EGID, 0));
    auxv.push((AT_SECURE, 0));
    auxv.push((AT_RANDOM, random_addr));
    auxv.push((AT_EXECFN, exec_name_addr));
    auxv.push((AT_NULL, 0));

    auxv
}
