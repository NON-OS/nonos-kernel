use crate::elf::types::{shdr_flags, shdr_type, SectionHeader};
use crate::test::framework::TestResult;
use core::mem;

pub(crate) fn test_section_header_size() -> TestResult {
    if mem::size_of::<SectionHeader>() != SectionHeader::SIZE {
        return TestResult::Fail;
    }
    if SectionHeader::SIZE != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_default() -> TestResult {
    let sh = SectionHeader::default();
    if sh.sh_name != 0 {
        return TestResult::Fail;
    }
    if sh.sh_type != 0 {
        return TestResult::Fail;
    }
    if sh.sh_flags != 0 {
        return TestResult::Fail;
    }
    if sh.sh_addr != 0 {
        return TestResult::Fail;
    }
    if sh.sh_offset != 0 {
        return TestResult::Fail;
    }
    if sh.sh_size != 0 {
        return TestResult::Fail;
    }
    if sh.sh_link != 0 {
        return TestResult::Fail;
    }
    if sh.sh_info != 0 {
        return TestResult::Fail;
    }
    if sh.sh_addralign != 0 {
        return TestResult::Fail;
    }
    if sh.sh_entsize != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_alloc_true() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_ALLOC;
    if !sh.is_alloc() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_alloc_false() -> TestResult {
    let sh = SectionHeader::default();
    if sh.is_alloc() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_alloc_with_other_flags() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE | shdr_flags::SHF_EXECINSTR;
    if !sh.is_alloc() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_writable_true() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_WRITE;
    if !sh.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_writable_false() -> TestResult {
    let sh = SectionHeader::default();
    if sh.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_writable_with_alloc() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE;
    if !sh.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_true() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_EXECINSTR;
    if !sh.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_false() -> TestResult {
    let sh = SectionHeader::default();
    if sh.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_with_alloc_read() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_EXECINSTR;
    if !sh.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_bss_true() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NOBITS;
    if !sh.is_bss() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_bss_false_progbits() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_PROGBITS;
    if sh.is_bss() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_bss_false_null() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NULL;
    if sh.is_bss() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_null() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NULL;
    if sh.type_name() != "NULL" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_progbits() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_PROGBITS;
    if sh.type_name() != "PROGBITS" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_symtab() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_SYMTAB;
    if sh.type_name() != "SYMTAB" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_strtab() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_STRTAB;
    if sh.type_name() != "STRTAB" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_rela() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_RELA;
    if sh.type_name() != "RELA" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_hash() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_HASH;
    if sh.type_name() != "HASH" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_dynamic() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_DYNAMIC;
    if sh.type_name() != "DYNAMIC" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_note() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NOTE;
    if sh.type_name() != "NOTE" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_nobits() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NOBITS;
    if sh.type_name() != "NOBITS" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_rel() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_REL;
    if sh.type_name() != "REL" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_dynsym() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_DYNSYM;
    if sh.type_name() != "DYNSYM" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_unknown() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = 0xFFFFFFFF;
    if sh.type_name() != "UNKNOWN" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_clone() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_addr = 0x400000;
    sh.sh_size = 0x1000;
    let cloned = sh;
    if cloned.sh_addr != 0x400000 {
        return TestResult::Fail;
    }
    if cloned.sh_size != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_copy() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_offset = 0x2000;
    let copied: SectionHeader = sh;
    if copied.sh_offset != 0x2000 {
        return TestResult::Fail;
    }
    if sh.sh_offset != 0x2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_alignment() -> TestResult {
    if mem::align_of::<SectionHeader>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_shdr_type_constants() -> TestResult {
    if shdr_type::SHT_NULL != 0 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_PROGBITS != 1 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_SYMTAB != 2 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_STRTAB != 3 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_RELA != 4 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_HASH != 5 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_DYNAMIC != 6 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_NOTE != 7 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_NOBITS != 8 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_REL != 9 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_SHLIB != 10 {
        return TestResult::Fail;
    }
    if shdr_type::SHT_DYNSYM != 11 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_shdr_flags_constants() -> TestResult {
    if shdr_flags::SHF_WRITE != 1 {
        return TestResult::Fail;
    }
    if shdr_flags::SHF_ALLOC != 2 {
        return TestResult::Fail;
    }
    if shdr_flags::SHF_EXECINSTR != 4 {
        return TestResult::Fail;
    }
    if shdr_flags::SHF_TLS != 0x400 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_text_section() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_PROGBITS;
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_EXECINSTR;
    sh.sh_addr = 0x401000;
    sh.sh_size = 0x5000;

    if sh.is_bss() {
        return TestResult::Fail;
    }
    if !sh.is_alloc() {
        return TestResult::Fail;
    }
    if sh.is_writable() {
        return TestResult::Fail;
    }
    if !sh.is_executable() {
        return TestResult::Fail;
    }
    if sh.type_name() != "PROGBITS" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_data_section() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_PROGBITS;
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE;
    sh.sh_addr = 0x600000;
    sh.sh_size = 0x1000;

    if sh.is_bss() {
        return TestResult::Fail;
    }
    if !sh.is_alloc() {
        return TestResult::Fail;
    }
    if !sh.is_writable() {
        return TestResult::Fail;
    }
    if sh.is_executable() {
        return TestResult::Fail;
    }
    if sh.type_name() != "PROGBITS" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_bss_section() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NOBITS;
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE;
    sh.sh_addr = 0x601000;
    sh.sh_size = 0x2000;

    if !sh.is_bss() {
        return TestResult::Fail;
    }
    if !sh.is_alloc() {
        return TestResult::Fail;
    }
    if !sh.is_writable() {
        return TestResult::Fail;
    }
    if sh.is_executable() {
        return TestResult::Fail;
    }
    if sh.type_name() != "NOBITS" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_tls_flag() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_TLS | shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE;
    if !sh.is_alloc() {
        return TestResult::Fail;
    }
    if !sh.is_writable() {
        return TestResult::Fail;
    }
    if (sh.sh_flags & shdr_flags::SHF_TLS) == 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_symtab_section() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_SYMTAB;
    sh.sh_link = 5;
    sh.sh_info = 10;
    sh.sh_entsize = 24;

    if sh.is_alloc() {
        return TestResult::Fail;
    }
    if sh.is_writable() {
        return TestResult::Fail;
    }
    if sh.is_executable() {
        return TestResult::Fail;
    }
    if sh.is_bss() {
        return TestResult::Fail;
    }
    if sh.type_name() != "SYMTAB" {
        return TestResult::Fail;
    }
    if sh.sh_entsize != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_section_header_rela_section() -> TestResult {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_RELA;
    sh.sh_flags = shdr_flags::SHF_ALLOC;
    sh.sh_link = 6;
    sh.sh_info = 12;
    sh.sh_entsize = 24;

    if !sh.is_alloc() {
        return TestResult::Fail;
    }
    if sh.is_writable() {
        return TestResult::Fail;
    }
    if sh.is_executable() {
        return TestResult::Fail;
    }
    if sh.is_bss() {
        return TestResult::Fail;
    }
    if sh.type_name() != "RELA" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
