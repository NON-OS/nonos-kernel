use crate::elf::types::{
    class, data, elf_type, ident, machine, ElfHeader, ProgramHeader, SectionHeader, ELF_MAGIC,
};
use core::mem;

#[test]
fn test_elf_header_size() {
    assert_eq!(mem::size_of::<ElfHeader>(), ElfHeader::SIZE);
    assert_eq!(ElfHeader::SIZE, 64);
}

#[test]
fn test_elf_header_default() {
    let header = ElfHeader::default();
    assert_eq!(header.ident, [0; 16]);
    assert_eq!(header.e_type, 0);
    assert_eq!(header.e_machine, 0);
    assert_eq!(header.e_version, 0);
    assert_eq!(header.e_entry, 0);
    assert_eq!(header.e_phoff, 0);
    assert_eq!(header.e_shoff, 0);
    assert_eq!(header.e_flags, 0);
    assert_eq!(header.e_ehsize, ElfHeader::SIZE as u16);
    assert_eq!(header.e_phentsize, ProgramHeader::SIZE as u16);
    assert_eq!(header.e_phnum, 0);
    assert_eq!(header.e_shentsize, SectionHeader::SIZE as u16);
    assert_eq!(header.e_shnum, 0);
    assert_eq!(header.e_shstrndx, 0);
}

#[test]
fn test_elf_magic_invalid() {
    let header = ElfHeader::default();
    assert!(!header.is_valid_magic());
}

#[test]
fn test_elf_magic_valid() {
    let mut header = ElfHeader::default();
    header.ident[0..4].copy_from_slice(&ELF_MAGIC);
    assert!(header.is_valid_magic());
}

#[test]
fn test_elf_magic_partial() {
    let mut header = ElfHeader::default();
    header.ident[0] = 0x7F;
    header.ident[1] = b'E';
    header.ident[2] = b'L';
    assert!(!header.is_valid_magic());
}

#[test]
fn test_elf_magic_wrong_bytes() {
    let mut header = ElfHeader::default();
    header.ident[0..4].copy_from_slice(&[0x7F, b'F', b'O', b'O']);
    assert!(!header.is_valid_magic());
}

#[test]
fn test_is_64bit_true() {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_CLASS] = class::ELFCLASS64;
    assert!(header.is_64bit());
}

#[test]
fn test_is_64bit_false_32bit() {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_CLASS] = class::ELFCLASS32;
    assert!(!header.is_64bit());
}

#[test]
fn test_is_64bit_false_none() {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_CLASS] = class::ELFCLASSNONE;
    assert!(!header.is_64bit());
}

#[test]
fn test_is_little_endian_true() {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_DATA] = data::ELFDATA2LSB;
    assert!(header.is_little_endian());
}

#[test]
fn test_is_little_endian_false_big() {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_DATA] = data::ELFDATA2MSB;
    assert!(!header.is_little_endian());
}

#[test]
fn test_is_little_endian_false_none() {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_DATA] = data::ELFDATANONE;
    assert!(!header.is_little_endian());
}

#[test]
fn test_is_executable_exec() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_EXEC;
    assert!(header.is_executable());
}

#[test]
fn test_is_executable_dyn() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_DYN;
    assert!(header.is_executable());
}

#[test]
fn test_is_executable_false_rel() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_REL;
    assert!(!header.is_executable());
}

#[test]
fn test_is_executable_false_core() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_CORE;
    assert!(!header.is_executable());
}

#[test]
fn test_is_executable_false_none() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_NONE;
    assert!(!header.is_executable());
}

#[test]
fn test_is_pie_true() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_DYN;
    assert!(header.is_pie());
}

#[test]
fn test_is_pie_false_exec() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_EXEC;
    assert!(!header.is_pie());
}

#[test]
fn test_is_x86_64_true() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_X86_64;
    assert!(header.is_x86_64());
}

#[test]
fn test_is_x86_64_false_386() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_386;
    assert!(!header.is_x86_64());
}

#[test]
fn test_is_x86_64_false_aarch64() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_AARCH64;
    assert!(!header.is_x86_64());
}

#[test]
fn test_is_x86_64_false_riscv() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_RISCV;
    assert!(!header.is_x86_64());
}

#[test]
fn test_type_name_none() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_NONE;
    assert_eq!(header.type_name(), "NONE");
}

#[test]
fn test_type_name_rel() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_REL;
    assert_eq!(header.type_name(), "REL");
}

#[test]
fn test_type_name_exec() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_EXEC;
    assert_eq!(header.type_name(), "EXEC");
}

#[test]
fn test_type_name_dyn() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_DYN;
    assert_eq!(header.type_name(), "DYN");
}

#[test]
fn test_type_name_core() {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_CORE;
    assert_eq!(header.type_name(), "CORE");
}

#[test]
fn test_type_name_unknown() {
    let mut header = ElfHeader::default();
    header.e_type = 0xFFFF;
    assert_eq!(header.type_name(), "UNKNOWN");
}

#[test]
fn test_machine_name_none() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_NONE;
    assert_eq!(header.machine_name(), "None");
}

#[test]
fn test_machine_name_386() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_386;
    assert_eq!(header.machine_name(), "Intel 80386");
}

#[test]
fn test_machine_name_x86_64() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_X86_64;
    assert_eq!(header.machine_name(), "AMD x86-64");
}

#[test]
fn test_machine_name_aarch64() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_AARCH64;
    assert_eq!(header.machine_name(), "AArch64");
}

#[test]
fn test_machine_name_riscv() {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_RISCV;
    assert_eq!(header.machine_name(), "RISC-V");
}

#[test]
fn test_machine_name_unknown() {
    let mut header = ElfHeader::default();
    header.e_machine = 0xFFFF;
    assert_eq!(header.machine_name(), "Unknown");
}

#[test]
fn test_elf_header_fully_configured() {
    let mut header = ElfHeader::default();
    header.ident[0..4].copy_from_slice(&ELF_MAGIC);
    header.ident[ident::EI_CLASS] = class::ELFCLASS64;
    header.ident[ident::EI_DATA] = data::ELFDATA2LSB;
    header.ident[ident::EI_VERSION] = 1;
    header.e_type = elf_type::ET_DYN;
    header.e_machine = machine::EM_X86_64;
    header.e_version = 1;
    header.e_entry = 0x401000;
    header.e_phoff = 64;
    header.e_shoff = 0x2000;
    header.e_phnum = 10;
    header.e_shnum = 20;
    header.e_shstrndx = 19;

    assert!(header.is_valid_magic());
    assert!(header.is_64bit());
    assert!(header.is_little_endian());
    assert!(header.is_executable());
    assert!(header.is_pie());
    assert!(header.is_x86_64());
    assert_eq!(header.type_name(), "DYN");
    assert_eq!(header.machine_name(), "AMD x86-64");
    assert_eq!(header.e_entry, 0x401000);
}

#[test]
fn test_elf_header_clone() {
    let mut header = ElfHeader::default();
    header.e_entry = 0x12345678;
    let cloned = header;
    assert_eq!(cloned.e_entry, 0x12345678);
}

#[test]
fn test_elf_header_copy() {
    let mut header = ElfHeader::default();
    header.e_entry = 0xABCDEF00;
    let copied: ElfHeader = header;
    assert_eq!(copied.e_entry, 0xABCDEF00);
    assert_eq!(header.e_entry, 0xABCDEF00);
}

#[test]
fn test_elf_header_alignment() {
    assert_eq!(mem::align_of::<ElfHeader>(), 8);
}

#[test]
fn test_elf_header_ident_indices() {
    assert_eq!(ident::EI_MAG0, 0);
    assert_eq!(ident::EI_CLASS, 4);
    assert_eq!(ident::EI_DATA, 5);
    assert_eq!(ident::EI_VERSION, 6);
    assert_eq!(ident::EI_OSABI, 7);
    assert_eq!(ident::EI_ABIVERSION, 8);
    assert_eq!(ident::EI_PAD, 9);
    assert_eq!(ident::EI_NIDENT, 16);
}

#[test]
fn test_elf_magic_bytes() {
    assert_eq!(ELF_MAGIC[0], 0x7F);
    assert_eq!(ELF_MAGIC[1], b'E');
    assert_eq!(ELF_MAGIC[2], b'L');
    assert_eq!(ELF_MAGIC[3], b'F');
}
