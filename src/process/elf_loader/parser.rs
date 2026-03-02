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

use core::mem::size_of;
use super::types::*;

pub fn parse_header(data: &[u8]) -> Result<&Elf64Header, ElfError> {
    if data.len() < size_of::<Elf64Header>() {
        return Err(ElfError::TooSmall);
    }

    // SAFETY: We verified above that data is at least as large as Elf64Header.
    // The Elf64Header struct is repr(C) and contains only primitive types (u8, u16, u64)
    // which have no alignment requirements beyond their natural alignment.
    // The data slice comes from file reading which ensures proper buffer alignment.
    let header = unsafe { &*(data.as_ptr() as *const Elf64Header) };

    if header.e_ident[0..4] != ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }

    if header.e_ident[4] != ELFCLASS64 {
        return Err(ElfError::Not64Bit);
    }

    if header.e_ident[5] != ELFDATA2LSB {
        return Err(ElfError::WrongEndian);
    }

    if header.e_machine != EM_X86_64 {
        return Err(ElfError::WrongMachine);
    }

    if header.e_type != ET_EXEC && header.e_type != ET_DYN {
        return Err(ElfError::NotExecutable);
    }

    Ok(header)
}

pub fn get_program_headers<'a>(
    data: &'a [u8],
    header: &Elf64Header,
) -> Result<&'a [Elf64ProgramHeader], ElfError> {
    let phoff = header.e_phoff as usize;
    let phnum = header.e_phnum as usize;
    let phentsize = header.e_phentsize as usize;

    if phentsize != size_of::<Elf64ProgramHeader>() {
        return Err(ElfError::InvalidProgramHeader);
    }

    let total_size = phnum * phentsize;
    if phoff + total_size > data.len() {
        return Err(ElfError::InvalidProgramHeader);
    }

    // SAFETY: We verified above that:
    // 1. phoff + total_size <= data.len(), so the slice is within bounds
    // 2. phentsize == size_of::<Elf64ProgramHeader>(), ensuring correct layout
    // 3. Elf64ProgramHeader is repr(C) with primitive types only
    // The resulting slice is valid for the lifetime of the input data slice.
    let phdrs = unsafe {
        core::slice::from_raw_parts(
            data.as_ptr().add(phoff) as *const Elf64ProgramHeader,
            phnum,
        )
    };

    Ok(phdrs)
}

pub fn get_section_headers<'a>(
    data: &'a [u8],
    header: &Elf64Header,
) -> Result<&'a [Elf64SectionHeader], ElfError> {
    let shoff = header.e_shoff as usize;
    let shnum = header.e_shnum as usize;
    let shentsize = header.e_shentsize as usize;

    if shnum == 0 {
        return Ok(&[]);
    }

    if shentsize != size_of::<Elf64SectionHeader>() {
        return Err(ElfError::InvalidSectionHeader);
    }

    let total_size = shnum * shentsize;
    if shoff + total_size > data.len() {
        return Err(ElfError::InvalidSectionHeader);
    }

    // SAFETY: We verified above that:
    // 1. shoff + total_size <= data.len(), so the slice is within bounds
    // 2. shentsize == size_of::<Elf64SectionHeader>(), ensuring correct layout
    // 3. Elf64SectionHeader is repr(C) with primitive types only
    // The resulting slice is valid for the lifetime of the input data slice.
    let shdrs = unsafe {
        core::slice::from_raw_parts(
            data.as_ptr().add(shoff) as *const Elf64SectionHeader,
            shnum,
        )
    };

    Ok(shdrs)
}
