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
use core::mem::size_of;
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
    let (_, _, ph_count) = program_header_bounds(elf_data, header)?;
    let mut program_headers = Vec::with_capacity(ph_count);
    for i in 0..ph_count {
        program_headers.push(parse_program_header_at(elf_data, header, i)?);
    }
    Ok(program_headers)
}

pub(super) fn program_header_bounds(
    elf_data: &[u8],
    header: &ElfHeader,
) -> Result<(usize, usize, usize), ElfError> {
    let ph_offset = header.e_phoff as usize;
    let ph_size = header.e_phentsize as usize;
    let ph_count = header.e_phnum as usize;
    if ph_size < size_of::<ProgramHeader>() {
        return Err(ElfError::ProgramHeadersOutOfBounds);
    }
    let table_bytes = ph_size.checked_mul(ph_count).ok_or(ElfError::ProgramHeadersOutOfBounds)?;
    let table_end =
        ph_offset.checked_add(table_bytes).ok_or(ElfError::ProgramHeadersOutOfBounds)?;
    if table_end > elf_data.len() {
        return Err(ElfError::ProgramHeadersOutOfBounds);
    }
    Ok((ph_offset, ph_size, ph_count))
}

pub(super) fn parse_program_header_at(
    elf_data: &[u8],
    header: &ElfHeader,
    index: usize,
) -> Result<ProgramHeader, ElfError> {
    let (ph_offset, ph_size, ph_count) = program_header_bounds(elf_data, header)?;
    if index >= ph_count {
        return Err(ElfError::ProgramHeadersOutOfBounds);
    }
    let off = ph_offset
        .checked_add(ph_size.checked_mul(index).ok_or(ElfError::ProgramHeadersOutOfBounds)?)
        .ok_or(ElfError::ProgramHeadersOutOfBounds)?;
    unsafe { Ok(ptr::read_unaligned(elf_data[off..].as_ptr() as *const ProgramHeader)) }
}
