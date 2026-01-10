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

use super::*;
use crate::elf::errors::ElfError;
use crate::elf::types::{elf_class, elf_data, elf_machine, elf_type, ELF_MAGIC};

fn make_valid_elf_header() -> [u8; 64] {
    let mut header = [0u8; 64];
    header[0..4].copy_from_slice(&ELF_MAGIC);
    header[4] = elf_class::ELFCLASS64;
    header[5] = elf_data::ELFDATA2LSB;
    header[6] = 1;
    header[16] = (elf_type::ET_EXEC & 0xFF) as u8;
    header[17] = ((elf_type::ET_EXEC >> 8) & 0xFF) as u8;
    header[18] = (elf_machine::EM_X86_64 & 0xFF) as u8;
    header[19] = ((elf_machine::EM_X86_64 >> 8) & 0xFF) as u8;
    header[24..32].copy_from_slice(&0x401000u64.to_le_bytes());
    header[32..40].copy_from_slice(&64u64.to_le_bytes());
    header[56..58].copy_from_slice(&3u16.to_le_bytes());
    header
}

#[test]
fn test_entry_from_bytes_valid() {
    let header = make_valid_elf_header();
    let entry = entry_from_bytes(&header).unwrap();
    assert_eq!(entry, 0x401000);
}

#[test]
fn test_entry_from_bytes_too_small() {
    let data = [0u8; 32];
    assert!(matches!(
        entry_from_bytes(&data),
        Err(ElfError::FileTooSmall)
    ));
}

#[test]
fn test_entry_from_bytes_invalid_magic() {
    let mut header = make_valid_elf_header();
    header[0] = 0;
    assert!(matches!(
        entry_from_bytes(&header),
        Err(ElfError::InvalidMagic)
    ));
}

#[test]
fn test_entry_from_bytes_zero_entry() {
    let mut header = make_valid_elf_header();
    header[24..32].copy_from_slice(&0u64.to_le_bytes());
    assert!(matches!(entry_from_bytes(&header), Err(ElfError::Other(_))));
}

#[test]
fn test_validate_elf_valid() {
    let header = make_valid_elf_header();
    assert!(validate_elf(&header));
}

#[test]
fn test_validate_elf_too_small() {
    let data = [0u8; 8];
    assert!(!validate_elf(&data));
}

#[test]
fn test_validate_elf_bad_magic() {
    let mut header = make_valid_elf_header();
    header[0] = 0;
    assert!(!validate_elf(&header));
}

#[test]
fn test_validate_elf_bad_class() {
    let mut header = make_valid_elf_header();
    header[4] = elf_class::ELFCLASS32;
    assert!(!validate_elf(&header));
}

#[test]
fn test_validate_elf_bad_endian() {
    let mut header = make_valid_elf_header();
    header[5] = elf_data::ELFDATA2MSB;
    assert!(!validate_elf(&header));
}

#[test]
fn test_validate_elf_detailed() {
    let header = make_valid_elf_header();
    assert!(validate_elf_detailed(&header).is_ok());
}

#[test]
fn test_validate_elf_detailed_bad_version() {
    let mut header = make_valid_elf_header();
    header[6] = 0;
    assert!(matches!(
        validate_elf_detailed(&header),
        Err(ElfError::InvalidVersion)
    ));
}

#[test]
fn test_validate_elf_x86_64() {
    let header = make_valid_elf_header();
    assert!(validate_elf_x86_64(&header).is_ok());
}

#[test]
fn test_validate_elf_x86_64_bad_machine() {
    let mut header = make_valid_elf_header();
    header[18] = 0;
    header[19] = 0;
    assert!(matches!(
        validate_elf_x86_64(&header),
        Err(ElfError::InvalidMachine)
    ));
}

#[test]
fn test_get_elf_type() {
    let header = make_valid_elf_header();
    assert_eq!(get_elf_type(&header).unwrap(), elf_type::ET_EXEC);
}

#[test]
fn test_get_elf_machine() {
    let header = make_valid_elf_header();
    assert_eq!(get_elf_machine(&header).unwrap(), elf_machine::EM_X86_64);
}

#[test]
fn test_is_pie() {
    let header = make_valid_elf_header();
    assert!(!is_pie(&header).unwrap());

    let mut pie_header = make_valid_elf_header();
    pie_header[16] = (elf_type::ET_DYN & 0xFF) as u8;
    pie_header[17] = ((elf_type::ET_DYN >> 8) & 0xFF) as u8;
    assert!(is_pie(&pie_header).unwrap());
}

#[test]
fn test_get_phoff() {
    let header = make_valid_elf_header();
    assert_eq!(get_phoff(&header).unwrap(), 64);
}

#[test]
fn test_get_phnum() {
    let header = make_valid_elf_header();
    assert_eq!(get_phnum(&header).unwrap(), 3);
}
