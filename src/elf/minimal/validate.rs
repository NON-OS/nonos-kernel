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

use crate::elf::errors::{ElfError, ElfResult};
use crate::elf::types::{elf_class, elf_data, elf_machine, elf_type, ElfHeader, ELF_MAGIC};

pub fn entry_from_bytes(elf_data: &[u8]) -> ElfResult<u64> {
    if elf_data.len() < ElfHeader::SIZE {
        return Err(ElfError::FileTooSmall);
    }

    if &elf_data[0..4] != ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }

    let entry_point = u64::from_le_bytes([
        elf_data[24],
        elf_data[25],
        elf_data[26],
        elf_data[27],
        elf_data[28],
        elf_data[29],
        elf_data[30],
        elf_data[31],
    ]);

    if entry_point == 0 {
        return Err(ElfError::Other("Invalid entry point"));
    }

    Ok(entry_point)
}

pub fn validate_elf(elf_bytes: &[u8]) -> bool {
    if elf_bytes.len() < 16 {
        return false;
    }

    if &elf_bytes[0..4] != ELF_MAGIC {
        return false;
    }

    if elf_bytes[4] != elf_class::ELFCLASS64 {
        return false;
    }

    if elf_bytes[5] != elf_data::ELFDATA2LSB {
        return false;
    }

    true
}

pub fn validate_elf_detailed(elf_bytes: &[u8]) -> ElfResult<()> {
    if elf_bytes.len() < ElfHeader::SIZE {
        return Err(ElfError::FileTooSmall);
    }

    if &elf_bytes[0..4] != ELF_MAGIC {
        return Err(ElfError::InvalidMagic);
    }

    if elf_bytes[4] != elf_class::ELFCLASS64 {
        return Err(ElfError::InvalidClass);
    }

    if elf_bytes[5] != elf_data::ELFDATA2LSB {
        return Err(ElfError::InvalidEndian);
    }

    if elf_bytes[6] != 1 {
        return Err(ElfError::InvalidVersion);
    }

    Ok(())
}

pub fn validate_elf_x86_64(elf_bytes: &[u8]) -> ElfResult<()> {
    validate_elf_detailed(elf_bytes)?;

    let machine = u16::from_le_bytes([elf_bytes[18], elf_bytes[19]]);
    if machine != elf_machine::EM_X86_64 {
        return Err(ElfError::InvalidMachine);
    }

    let elf_type_val = u16::from_le_bytes([elf_bytes[16], elf_bytes[17]]);
    if elf_type_val != elf_type::ET_EXEC && elf_type_val != elf_type::ET_DYN {
        return Err(ElfError::InvalidType);
    }

    Ok(())
}

pub fn get_elf_type(elf_bytes: &[u8]) -> ElfResult<u16> {
    if elf_bytes.len() < 18 {
        return Err(ElfError::FileTooSmall);
    }

    if !validate_elf(elf_bytes) {
        return Err(ElfError::InvalidMagic);
    }

    Ok(u16::from_le_bytes([elf_bytes[16], elf_bytes[17]]))
}

pub fn get_elf_machine(elf_bytes: &[u8]) -> ElfResult<u16> {
    if elf_bytes.len() < 20 {
        return Err(ElfError::FileTooSmall);
    }

    if !validate_elf(elf_bytes) {
        return Err(ElfError::InvalidMagic);
    }

    Ok(u16::from_le_bytes([elf_bytes[18], elf_bytes[19]]))
}

pub fn is_pie(elf_bytes: &[u8]) -> ElfResult<bool> {
    let elf_type_val = get_elf_type(elf_bytes)?;
    Ok(elf_type_val == elf_type::ET_DYN)
}

pub fn get_phoff(elf_bytes: &[u8]) -> ElfResult<u64> {
    if elf_bytes.len() < 40 {
        return Err(ElfError::FileTooSmall);
    }

    if !validate_elf(elf_bytes) {
        return Err(ElfError::InvalidMagic);
    }

    Ok(u64::from_le_bytes([
        elf_bytes[32],
        elf_bytes[33],
        elf_bytes[34],
        elf_bytes[35],
        elf_bytes[36],
        elf_bytes[37],
        elf_bytes[38],
        elf_bytes[39],
    ]))
}

pub fn get_shoff(elf_bytes: &[u8]) -> ElfResult<u64> {
    if elf_bytes.len() < 48 {
        return Err(ElfError::FileTooSmall);
    }

    if !validate_elf(elf_bytes) {
        return Err(ElfError::InvalidMagic);
    }

    Ok(u64::from_le_bytes([
        elf_bytes[40],
        elf_bytes[41],
        elf_bytes[42],
        elf_bytes[43],
        elf_bytes[44],
        elf_bytes[45],
        elf_bytes[46],
        elf_bytes[47],
    ]))
}

pub fn get_phnum(elf_bytes: &[u8]) -> ElfResult<u16> {
    if elf_bytes.len() < 58 {
        return Err(ElfError::FileTooSmall);
    }

    if !validate_elf(elf_bytes) {
        return Err(ElfError::InvalidMagic);
    }

    Ok(u16::from_le_bytes([elf_bytes[56], elf_bytes[57]]))
}

pub fn get_shnum(elf_bytes: &[u8]) -> ElfResult<u16> {
    if elf_bytes.len() < 62 {
        return Err(ElfError::FileTooSmall);
    }

    if !validate_elf(elf_bytes) {
        return Err(ElfError::InvalidMagic);
    }

    Ok(u16::from_le_bytes([elf_bytes[60], elf_bytes[61]]))
}
