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

extern crate alloc;

use alloc::string::ToString;
use alloc::vec;

use super::*;
use crate::elf::errors::ElfError;
use crate::elf::types::ProgramHeader;

#[test]
fn test_interpreter_info_new() {
    let info = InterpreterInfo::new("/lib64/ld-linux-x86-64.so.2".into());
    assert_eq!(info.path, "/lib64/ld-linux-x86-64.so.2");
}

#[test]
fn test_interpreter_info_as_str() {
    let info = InterpreterInfo::new("/lib64/ld-linux-x86-64.so.2".into());
    assert_eq!(info.as_str(), "/lib64/ld-linux-x86-64.so.2");
}

#[test]
fn test_is_nonos_ld() {
    let info = InterpreterInfo::new(NONOS_INTERP.into());
    assert!(info.is_nonos_ld());

    let info2 = InterpreterInfo::new("/lib/ld-nonos.so.2".into());
    assert!(info2.is_nonos_ld());

    let foreign = InterpreterInfo::new("/lib64/ld-linux-x86-64.so.2".into());
    assert!(!foreign.is_nonos_ld());
}

#[test]
fn test_is_glibc_ld() {
    let info = InterpreterInfo::new("/lib64/ld-linux-x86-64.so.2".into());
    assert!(info.is_glibc_ld());

    let info2 = InterpreterInfo::new("/lib/ld-linux.so.2".into());
    assert!(info2.is_glibc_ld());

    let nonos = InterpreterInfo::new(NONOS_INTERP.into());
    assert!(!nonos.is_glibc_ld());
}

#[test]
fn test_is_musl_ld() {
    let info = InterpreterInfo::new("/lib/ld-musl-x86_64.so.1".into());
    assert!(info.is_musl_ld());

    let info2 = InterpreterInfo::new("/lib/ld-musl-aarch64.so.1".into());
    assert!(info2.is_musl_ld());

    let nonos = InterpreterInfo::new(NONOS_INTERP.into());
    assert!(!nonos.is_musl_ld());
}

#[test]
fn test_is_foreign() {
    let glibc = InterpreterInfo::new("/lib64/ld-linux-x86-64.so.2".into());
    assert!(glibc.is_foreign());

    let musl = InterpreterInfo::new("/lib/ld-musl-x86_64.so.1".into());
    assert!(musl.is_foreign());

    let nonos = InterpreterInfo::new(NONOS_INTERP.into());
    assert!(!nonos.is_foreign());
}

#[test]
fn test_filename() {
    let info = InterpreterInfo::new("/lib64/ld-linux-x86-64.so.2".into());
    assert_eq!(info.filename(), "ld-linux-x86-64.so.2");

    let info2 = InterpreterInfo::new("ld.so".into());
    assert_eq!(info2.filename(), "ld.so");
}

#[test]
fn test_is_absolute() {
    let info = InterpreterInfo::new("/lib64/ld-linux-x86-64.so.2".into());
    assert!(info.is_absolute());

    let info2 = InterpreterInfo::new("ld.so".into());
    assert!(!info2.is_absolute());
}

#[test]
fn test_directory() {
    let info = InterpreterInfo::new("/lib64/ld-linux-x86-64.so.2".into());
    assert_eq!(info.directory(), "/lib64");

    let info2 = InterpreterInfo::new("/a/b/c/ld.so".into());
    assert_eq!(info2.directory(), "/a/b/c");

    let info3 = InterpreterInfo::new("ld.so".into());
    assert_eq!(info3.directory(), "");
}

#[test]
fn test_default() {
    let info = InterpreterInfo::default();
    assert!(info.path.is_empty());
}

#[test]
fn test_from_string() {
    let info: InterpreterInfo = "/lib64/ld-linux-x86-64.so.2".to_string().into();
    assert_eq!(info.path, "/lib64/ld-linux-x86-64.so.2");
}

#[test]
fn test_from_str() {
    let info: InterpreterInfo = "/lib64/ld-linux-x86-64.so.2".into();
    assert_eq!(info.path, "/lib64/ld-linux-x86-64.so.2");
}

#[test]
fn test_from_elf_valid() {
    let mut elf_data = vec![0u8; 100];
    let path = b"/lib64/ld-linux-x86-64.so.2\0";
    elf_data[10..10 + path.len()].copy_from_slice(path);

    let ph = ProgramHeader {
        p_type: 3,
        p_flags: 0,
        p_offset: 10,
        p_vaddr: 0,
        p_paddr: 0,
        p_filesz: path.len() as u64,
        p_memsz: path.len() as u64,
        p_align: 1,
    };

    let info = InterpreterInfo::from_elf(&elf_data, &ph).unwrap();
    assert_eq!(info.path, "/lib64/ld-linux-x86-64.so.2");
}

#[test]
fn test_from_elf_out_of_bounds() {
    let elf_data = vec![0u8; 10];
    let ph = ProgramHeader {
        p_type: 3,
        p_flags: 0,
        p_offset: 5,
        p_vaddr: 0,
        p_paddr: 0,
        p_filesz: 20,
        p_memsz: 20,
        p_align: 1,
    };

    let result = InterpreterInfo::from_elf(&elf_data, &ph);
    assert!(matches!(result, Err(ElfError::InterpreterNotFound)));
}

#[test]
fn test_from_elf_empty() {
    let elf_data = vec![0u8; 100];
    let ph = ProgramHeader {
        p_type: 3,
        p_flags: 0,
        p_offset: 10,
        p_vaddr: 0,
        p_paddr: 0,
        p_filesz: 0,
        p_memsz: 0,
        p_align: 1,
    };

    let result = InterpreterInfo::from_elf(&elf_data, &ph);
    assert!(matches!(result, Err(ElfError::InterpreterNotFound)));
}

#[test]
fn test_constants() {
    assert_eq!(NONOS_INTERP, "/lib/ld-nonos.so.1");
    assert_eq!(MAX_INTERP_PATH_LEN, 4096);
    assert_eq!(known_interp::GLIBC_LD, "ld-linux");
    assert_eq!(known_interp::MUSL_LD, "ld-musl");
    assert_eq!(known_interp::GENERIC_LD, "ld.so");
}
