//! Minimal ELF entry point extraction

#![no_std]

use super::types::ElfHeader;

/// Extract entry point from ELF bytes
pub fn entry_from_bytes(elf_data: &[u8]) -> Result<u64, &'static str> {
    if elf_data.len() < core::mem::size_of::<ElfHeader>() {
        return Err("ELF data too small");
    }

    // Check ELF magic
    if &elf_data[0..4] != b"\x7fELF" {
        return Err("Invalid ELF magic");
    }

    // Extract entry point from ELF header
    // Entry point is at offset 24 for 64-bit ELF
    if elf_data.len() < 32 {
        return Err("ELF header incomplete");
    }

    let entry_point = u64::from_le_bytes([
        elf_data[24], elf_data[25], elf_data[26], elf_data[27],
        elf_data[28], elf_data[29], elf_data[30], elf_data[31],
    ]);

    if entry_point == 0 {
        return Err("Invalid entry point");
    }

    Ok(entry_point)
}

/// Basic ELF validation
pub fn validate_elf(elf_data: &[u8]) -> bool {
    if elf_data.len() < 16 {
        return false;
    }

    // Check magic
    if &elf_data[0..4] != b"\x7fELF" {
        return false;
    }

    // Check class (64-bit)
    if elf_data[4] != 2 {
        return false;
    }

    // Check endianness (little endian)
    if elf_data[5] != 1 {
        return false;
    }

    true
}