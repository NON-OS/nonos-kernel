use crate::elf::types::{
    class, data, elf_type, ident, machine, ElfHeader, ProgramHeader, SectionHeader, ELF_MAGIC,
};
use crate::test::framework::TestResult;
use core::mem;

pub(crate) fn test_elf_header_size() -> TestResult {
    if mem::size_of::<ElfHeader>() != ElfHeader::SIZE {
        return TestResult::Fail;
    }
    if ElfHeader::SIZE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_header_default() -> TestResult {
    let header = ElfHeader::default();
    if header.ident != [0; 16] {
        return TestResult::Fail;
    }
    if header.e_type != 0 {
        return TestResult::Fail;
    }
    if header.e_machine != 0 {
        return TestResult::Fail;
    }
    if header.e_version != 0 {
        return TestResult::Fail;
    }
    if header.e_entry != 0 {
        return TestResult::Fail;
    }
    if header.e_phoff != 0 {
        return TestResult::Fail;
    }
    if header.e_shoff != 0 {
        return TestResult::Fail;
    }
    if header.e_flags != 0 {
        return TestResult::Fail;
    }
    if header.e_ehsize != ElfHeader::SIZE as u16 {
        return TestResult::Fail;
    }
    if header.e_phentsize != ProgramHeader::SIZE as u16 {
        return TestResult::Fail;
    }
    if header.e_phnum != 0 {
        return TestResult::Fail;
    }
    if header.e_shentsize != SectionHeader::SIZE as u16 {
        return TestResult::Fail;
    }
    if header.e_shnum != 0 {
        return TestResult::Fail;
    }
    if header.e_shstrndx != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_magic_invalid() -> TestResult {
    let header = ElfHeader::default();
    if header.is_valid_magic() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_magic_valid() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[0..4].copy_from_slice(&ELF_MAGIC);
    if !header.is_valid_magic() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_magic_partial() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[0] = 0x7F;
    header.ident[1] = b'E';
    header.ident[2] = b'L';
    if header.is_valid_magic() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_magic_wrong_bytes() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[0..4].copy_from_slice(&[0x7F, b'F', b'O', b'O']);
    if header.is_valid_magic() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_64bit_true() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_CLASS] = class::ELFCLASS64;
    if !header.is_64bit() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_64bit_false_32bit() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_CLASS] = class::ELFCLASS32;
    if header.is_64bit() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_64bit_false_none() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_CLASS] = class::ELFCLASSNONE;
    if header.is_64bit() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_little_endian_true() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_DATA] = data::ELFDATA2LSB;
    if !header.is_little_endian() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_little_endian_false_big() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_DATA] = data::ELFDATA2MSB;
    if header.is_little_endian() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_little_endian_false_none() -> TestResult {
    let mut header = ElfHeader::default();
    header.ident[ident::EI_DATA] = data::ELFDATANONE;
    if header.is_little_endian() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_exec() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_EXEC;
    if !header.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_dyn() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_DYN;
    if !header.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_false_rel() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_REL;
    if header.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_false_core() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_CORE;
    if header.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_false_none() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_NONE;
    if header.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_pie_true() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_DYN;
    if !header.is_pie() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_pie_false_exec() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_EXEC;
    if header.is_pie() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_x86_64_true() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_X86_64;
    if !header.is_x86_64() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_x86_64_false_386() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_386;
    if header.is_x86_64() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_x86_64_false_aarch64() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_AARCH64;
    if header.is_x86_64() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_x86_64_false_riscv() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_RISCV;
    if header.is_x86_64() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_none() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_NONE;
    if header.type_name() != "NONE" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_rel() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_REL;
    if header.type_name() != "REL" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_exec() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_EXEC;
    if header.type_name() != "EXEC" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_dyn() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_DYN;
    if header.type_name() != "DYN" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_core() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = elf_type::ET_CORE;
    if header.type_name() != "CORE" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_unknown() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_type = 0xFFFF;
    if header.type_name() != "UNKNOWN" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_machine_name_none() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_NONE;
    if header.machine_name() != "None" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_machine_name_386() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_386;
    if header.machine_name() != "Intel 80386" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_machine_name_x86_64() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_X86_64;
    if header.machine_name() != "AMD x86-64" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_machine_name_aarch64() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_AARCH64;
    if header.machine_name() != "AArch64" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_machine_name_riscv() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = machine::EM_RISCV;
    if header.machine_name() != "RISC-V" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_machine_name_unknown() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_machine = 0xFFFF;
    if header.machine_name() != "Unknown" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_header_fully_configured() -> TestResult {
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

    if !header.is_valid_magic() {
        return TestResult::Fail;
    }
    if !header.is_64bit() {
        return TestResult::Fail;
    }
    if !header.is_little_endian() {
        return TestResult::Fail;
    }
    if !header.is_executable() {
        return TestResult::Fail;
    }
    if !header.is_pie() {
        return TestResult::Fail;
    }
    if !header.is_x86_64() {
        return TestResult::Fail;
    }
    if header.type_name() != "DYN" {
        return TestResult::Fail;
    }
    if header.machine_name() != "AMD x86-64" {
        return TestResult::Fail;
    }
    if header.e_entry != 0x401000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_header_clone() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_entry = 0x12345678;
    let cloned = header;
    if cloned.e_entry != 0x12345678 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_header_copy() -> TestResult {
    let mut header = ElfHeader::default();
    header.e_entry = 0xABCDEF00;
    let copied: ElfHeader = header;
    if copied.e_entry != 0xABCDEF00 {
        return TestResult::Fail;
    }
    if header.e_entry != 0xABCDEF00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_header_alignment() -> TestResult {
    if mem::align_of::<ElfHeader>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_header_ident_indices() -> TestResult {
    if ident::EI_MAG0 != 0 {
        return TestResult::Fail;
    }
    if ident::EI_CLASS != 4 {
        return TestResult::Fail;
    }
    if ident::EI_DATA != 5 {
        return TestResult::Fail;
    }
    if ident::EI_VERSION != 6 {
        return TestResult::Fail;
    }
    if ident::EI_OSABI != 7 {
        return TestResult::Fail;
    }
    if ident::EI_ABIVERSION != 8 {
        return TestResult::Fail;
    }
    if ident::EI_PAD != 9 {
        return TestResult::Fail;
    }
    if ident::EI_NIDENT != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_elf_magic_bytes() -> TestResult {
    if ELF_MAGIC[0] != 0x7F {
        return TestResult::Fail;
    }
    if ELF_MAGIC[1] != b'E' {
        return TestResult::Fail;
    }
    if ELF_MAGIC[2] != b'L' {
        return TestResult::Fail;
    }
    if ELF_MAGIC[3] != b'F' {
        return TestResult::Fail;
    }
    TestResult::Pass
}
