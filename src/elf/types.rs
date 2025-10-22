//! ELF Header and Related Types for NØNOS Kernel

use x86_64::VirtAddr;

/// ELF header structure
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ElfHeader {
    pub ident: [u8; 16],
    pub e_type: u16,
    pub e_machine: u16,
    pub e_version: u32,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_shoff: u64,
    pub e_flags: u32,
    pub e_ehsize: u16,
    pub e_phentsize: u16,
    pub e_phnum: u16,
    pub e_shentsize: u16,
    pub e_shnum: u16,
    pub e_shstrndx: u16,
}

/// Program header
#[repr(C)]
#[derive(Debug, Clone)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

/// Section header
#[repr(C)]
#[derive(Debug, Clone)]
pub struct SectionHeader {
    pub sh_name: u32,
    pub sh_type: u32,
    pub sh_flags: u64,
    pub sh_addr: u64,
    pub sh_offset: u64,
    pub sh_size: u64,
    pub sh_link: u32,
    pub sh_info: u32,
    pub sh_addralign: u64,
    pub sh_entsize: u64,
}

/// Symbol table entry
#[repr(C)]
#[derive(Debug, Clone)]
pub struct Symbol {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

/// Relocation entry with addend
#[repr(C)]
#[derive(Debug, Clone)]
pub struct RelaEntry {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

/// Dynamic section entry
#[repr(C)]
#[derive(Debug, Clone)]
pub struct DynamicEntry {
    pub d_tag: u64,
    pub value: u64,
}
