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

extern crate alloc;
use crate::elf::errors::ElfError;
use crate::elf::types::*;
use alloc::vec::Vec;
use core::ptr;

pub(super) fn parse_elf_header(elf_data: &[u8]) -> Result<ElfHeader, ElfError> {
    if elf_data.len() < ElfHeader::SIZE {
        return Err(ElfError::FileTooSmall);
    }
    unsafe { Ok(ptr::read_unaligned(elf_data.as_ptr() as *const ElfHeader)) }
}

pub(super) fn validate_elf(header: &ElfHeader) -> Result<(), ElfError> {
    if !header.is_valid_magic() {
        return Err(ElfError::InvalidMagic);
    }
    if !header.is_64bit() {
        return Err(ElfError::InvalidClass);
    }
    if !header.is_little_endian() {
        return Err(ElfError::InvalidEndian);
    }
    if header.ident[6] != 1 {
        return Err(ElfError::InvalidVersion);
    }
    if header.e_machine != elf_machine::EM_X86_64 {
        return Err(ElfError::InvalidMachine);
    }
    if header.e_type != elf_type::ET_EXEC && header.e_type != elf_type::ET_DYN {
        return Err(ElfError::InvalidType);
    }
    Ok(())
}

pub(super) fn parse_program_headers(
    elf_data: &[u8],
    header: &ElfHeader,
) -> Result<Vec<ProgramHeader>, ElfError> {
    let (ph_offset, ph_size, ph_count) =
        (header.e_phoff as usize, header.e_phentsize as usize, header.e_phnum as usize);
    if ph_offset + (ph_size * ph_count) > elf_data.len() {
        return Err(ElfError::ProgramHeadersOutOfBounds);
    }
    let mut program_headers = Vec::with_capacity(ph_count);
    for i in 0..ph_count {
        unsafe {
            program_headers.push(ptr::read_unaligned(
                elf_data[ph_offset + i * ph_size..].as_ptr() as *const ProgramHeader,
            ));
        }
    }
    Ok(program_headers)
}
