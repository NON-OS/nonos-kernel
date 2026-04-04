use crate::elf::types::{shdr_flags, shdr_type, SectionHeader};
use core::mem;

#[test]
fn test_section_header_size() {
    assert_eq!(mem::size_of::<SectionHeader>(), SectionHeader::SIZE);
    assert_eq!(SectionHeader::SIZE, 64);
}

#[test]
fn test_section_header_default() {
    let sh = SectionHeader::default();
    assert_eq!(sh.sh_name, 0);
    assert_eq!(sh.sh_type, 0);
    assert_eq!(sh.sh_flags, 0);
    assert_eq!(sh.sh_addr, 0);
    assert_eq!(sh.sh_offset, 0);
    assert_eq!(sh.sh_size, 0);
    assert_eq!(sh.sh_link, 0);
    assert_eq!(sh.sh_info, 0);
    assert_eq!(sh.sh_addralign, 0);
    assert_eq!(sh.sh_entsize, 0);
}

#[test]
fn test_is_alloc_true() {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_ALLOC;
    assert!(sh.is_alloc());
}

#[test]
fn test_is_alloc_false() {
    let sh = SectionHeader::default();
    assert!(!sh.is_alloc());
}

#[test]
fn test_is_alloc_with_other_flags() {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE | shdr_flags::SHF_EXECINSTR;
    assert!(sh.is_alloc());
}

#[test]
fn test_is_writable_true() {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_WRITE;
    assert!(sh.is_writable());
}

#[test]
fn test_is_writable_false() {
    let sh = SectionHeader::default();
    assert!(!sh.is_writable());
}

#[test]
fn test_is_writable_with_alloc() {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE;
    assert!(sh.is_writable());
}

#[test]
fn test_is_executable_true() {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_EXECINSTR;
    assert!(sh.is_executable());
}

#[test]
fn test_is_executable_false() {
    let sh = SectionHeader::default();
    assert!(!sh.is_executable());
}

#[test]
fn test_is_executable_with_alloc_read() {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_EXECINSTR;
    assert!(sh.is_executable());
}

#[test]
fn test_is_bss_true() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NOBITS;
    assert!(sh.is_bss());
}

#[test]
fn test_is_bss_false_progbits() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_PROGBITS;
    assert!(!sh.is_bss());
}

#[test]
fn test_is_bss_false_null() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NULL;
    assert!(!sh.is_bss());
}

#[test]
fn test_type_name_null() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NULL;
    assert_eq!(sh.type_name(), "NULL");
}

#[test]
fn test_type_name_progbits() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_PROGBITS;
    assert_eq!(sh.type_name(), "PROGBITS");
}

#[test]
fn test_type_name_symtab() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_SYMTAB;
    assert_eq!(sh.type_name(), "SYMTAB");
}

#[test]
fn test_type_name_strtab() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_STRTAB;
    assert_eq!(sh.type_name(), "STRTAB");
}

#[test]
fn test_type_name_rela() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_RELA;
    assert_eq!(sh.type_name(), "RELA");
}

#[test]
fn test_type_name_hash() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_HASH;
    assert_eq!(sh.type_name(), "HASH");
}

#[test]
fn test_type_name_dynamic() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_DYNAMIC;
    assert_eq!(sh.type_name(), "DYNAMIC");
}

#[test]
fn test_type_name_note() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NOTE;
    assert_eq!(sh.type_name(), "NOTE");
}

#[test]
fn test_type_name_nobits() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NOBITS;
    assert_eq!(sh.type_name(), "NOBITS");
}

#[test]
fn test_type_name_rel() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_REL;
    assert_eq!(sh.type_name(), "REL");
}

#[test]
fn test_type_name_dynsym() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_DYNSYM;
    assert_eq!(sh.type_name(), "DYNSYM");
}

#[test]
fn test_type_name_unknown() {
    let mut sh = SectionHeader::default();
    sh.sh_type = 0xFFFFFFFF;
    assert_eq!(sh.type_name(), "UNKNOWN");
}

#[test]
fn test_section_header_clone() {
    let mut sh = SectionHeader::default();
    sh.sh_addr = 0x400000;
    sh.sh_size = 0x1000;
    let cloned = sh;
    assert_eq!(cloned.sh_addr, 0x400000);
    assert_eq!(cloned.sh_size, 0x1000);
}

#[test]
fn test_section_header_copy() {
    let mut sh = SectionHeader::default();
    sh.sh_offset = 0x2000;
    let copied: SectionHeader = sh;
    assert_eq!(copied.sh_offset, 0x2000);
    assert_eq!(sh.sh_offset, 0x2000);
}

#[test]
fn test_section_header_alignment() {
    assert_eq!(mem::align_of::<SectionHeader>(), 8);
}

#[test]
fn test_shdr_type_constants() {
    assert_eq!(shdr_type::SHT_NULL, 0);
    assert_eq!(shdr_type::SHT_PROGBITS, 1);
    assert_eq!(shdr_type::SHT_SYMTAB, 2);
    assert_eq!(shdr_type::SHT_STRTAB, 3);
    assert_eq!(shdr_type::SHT_RELA, 4);
    assert_eq!(shdr_type::SHT_HASH, 5);
    assert_eq!(shdr_type::SHT_DYNAMIC, 6);
    assert_eq!(shdr_type::SHT_NOTE, 7);
    assert_eq!(shdr_type::SHT_NOBITS, 8);
    assert_eq!(shdr_type::SHT_REL, 9);
    assert_eq!(shdr_type::SHT_SHLIB, 10);
    assert_eq!(shdr_type::SHT_DYNSYM, 11);
}

#[test]
fn test_shdr_flags_constants() {
    assert_eq!(shdr_flags::SHF_WRITE, 1);
    assert_eq!(shdr_flags::SHF_ALLOC, 2);
    assert_eq!(shdr_flags::SHF_EXECINSTR, 4);
    assert_eq!(shdr_flags::SHF_TLS, 0x400);
}

#[test]
fn test_section_header_text_section() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_PROGBITS;
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_EXECINSTR;
    sh.sh_addr = 0x401000;
    sh.sh_size = 0x5000;

    assert!(!sh.is_bss());
    assert!(sh.is_alloc());
    assert!(!sh.is_writable());
    assert!(sh.is_executable());
    assert_eq!(sh.type_name(), "PROGBITS");
}

#[test]
fn test_section_header_data_section() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_PROGBITS;
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE;
    sh.sh_addr = 0x600000;
    sh.sh_size = 0x1000;

    assert!(!sh.is_bss());
    assert!(sh.is_alloc());
    assert!(sh.is_writable());
    assert!(!sh.is_executable());
    assert_eq!(sh.type_name(), "PROGBITS");
}

#[test]
fn test_section_header_bss_section() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_NOBITS;
    sh.sh_flags = shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE;
    sh.sh_addr = 0x601000;
    sh.sh_size = 0x2000;

    assert!(sh.is_bss());
    assert!(sh.is_alloc());
    assert!(sh.is_writable());
    assert!(!sh.is_executable());
    assert_eq!(sh.type_name(), "NOBITS");
}

#[test]
fn test_section_header_tls_flag() {
    let mut sh = SectionHeader::default();
    sh.sh_flags = shdr_flags::SHF_TLS | shdr_flags::SHF_ALLOC | shdr_flags::SHF_WRITE;
    assert!(sh.is_alloc());
    assert!(sh.is_writable());
    assert!((sh.sh_flags & shdr_flags::SHF_TLS) != 0);
}

#[test]
fn test_section_header_symtab_section() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_SYMTAB;
    sh.sh_link = 5;
    sh.sh_info = 10;
    sh.sh_entsize = 24;

    assert!(!sh.is_alloc());
    assert!(!sh.is_writable());
    assert!(!sh.is_executable());
    assert!(!sh.is_bss());
    assert_eq!(sh.type_name(), "SYMTAB");
    assert_eq!(sh.sh_entsize, 24);
}

#[test]
fn test_section_header_rela_section() {
    let mut sh = SectionHeader::default();
    sh.sh_type = shdr_type::SHT_RELA;
    sh.sh_flags = shdr_flags::SHF_ALLOC;
    sh.sh_link = 6;
    sh.sh_info = 12;
    sh.sh_entsize = 24;

    assert!(sh.is_alloc());
    assert!(!sh.is_writable());
    assert!(!sh.is_executable());
    assert!(!sh.is_bss());
    assert_eq!(sh.type_name(), "RELA");
}
