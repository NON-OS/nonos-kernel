use crate::elf::types::{phdr_flags, phdr_type, ProgramHeader};
use core::mem;

#[test]
fn test_program_header_size() {
    assert_eq!(mem::size_of::<ProgramHeader>(), ProgramHeader::SIZE);
    assert_eq!(ProgramHeader::SIZE, 56);
}

#[test]
fn test_program_header_default() {
    let ph = ProgramHeader::default();
    assert_eq!(ph.p_type, 0);
    assert_eq!(ph.p_flags, 0);
    assert_eq!(ph.p_offset, 0);
    assert_eq!(ph.p_vaddr, 0);
    assert_eq!(ph.p_paddr, 0);
    assert_eq!(ph.p_filesz, 0);
    assert_eq!(ph.p_memsz, 0);
    assert_eq!(ph.p_align, 0);
}

#[test]
fn test_is_load_true() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_LOAD;
    assert!(ph.is_load());
}

#[test]
fn test_is_load_false_null() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_NULL;
    assert!(!ph.is_load());
}

#[test]
fn test_is_load_false_dynamic() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_DYNAMIC;
    assert!(!ph.is_load());
}

#[test]
fn test_is_load_false_interp() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_INTERP;
    assert!(!ph.is_load());
}

#[test]
fn test_is_readable_true() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R;
    assert!(ph.is_readable());
}

#[test]
fn test_is_readable_false() {
    let ph = ProgramHeader::default();
    assert!(!ph.is_readable());
}

#[test]
fn test_is_readable_with_other_flags() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_W | phdr_flags::PF_X;
    assert!(ph.is_readable());
}

#[test]
fn test_is_writable_true() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_W;
    assert!(ph.is_writable());
}

#[test]
fn test_is_writable_false() {
    let ph = ProgramHeader::default();
    assert!(!ph.is_writable());
}

#[test]
fn test_is_writable_with_read() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_W;
    assert!(ph.is_writable());
}

#[test]
fn test_is_executable_true() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_X;
    assert!(ph.is_executable());
}

#[test]
fn test_is_executable_false() {
    let ph = ProgramHeader::default();
    assert!(!ph.is_executable());
}

#[test]
fn test_is_executable_with_read() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_X;
    assert!(ph.is_executable());
}

#[test]
fn test_bss_size_no_bss() {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0x1000;
    ph.p_memsz = 0x1000;
    assert_eq!(ph.bss_size(), 0);
}

#[test]
fn test_bss_size_with_bss() {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0x1000;
    ph.p_memsz = 0x2000;
    assert_eq!(ph.bss_size(), 0x1000);
}

#[test]
fn test_bss_size_large_bss() {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0x100;
    ph.p_memsz = 0x10000;
    assert_eq!(ph.bss_size(), 0xFF00);
}

#[test]
fn test_bss_size_zero_filesz() {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0;
    ph.p_memsz = 0x1000;
    assert_eq!(ph.bss_size(), 0x1000);
}

#[test]
fn test_bss_size_saturating() {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0x2000;
    ph.p_memsz = 0x1000;
    assert_eq!(ph.bss_size(), 0);
}

#[test]
fn test_type_name_null() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_NULL;
    assert_eq!(ph.type_name(), "NULL");
}

#[test]
fn test_type_name_load() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_LOAD;
    assert_eq!(ph.type_name(), "LOAD");
}

#[test]
fn test_type_name_dynamic() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_DYNAMIC;
    assert_eq!(ph.type_name(), "DYNAMIC");
}

#[test]
fn test_type_name_interp() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_INTERP;
    assert_eq!(ph.type_name(), "INTERP");
}

#[test]
fn test_type_name_note() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_NOTE;
    assert_eq!(ph.type_name(), "NOTE");
}

#[test]
fn test_type_name_phdr() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_PHDR;
    assert_eq!(ph.type_name(), "PHDR");
}

#[test]
fn test_type_name_tls() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_TLS;
    assert_eq!(ph.type_name(), "TLS");
}

#[test]
fn test_type_name_gnu_stack() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_GNU_STACK;
    assert_eq!(ph.type_name(), "GNU_STACK");
}

#[test]
fn test_type_name_gnu_relro() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_GNU_RELRO;
    assert_eq!(ph.type_name(), "GNU_RELRO");
}

#[test]
fn test_type_name_unknown() {
    let mut ph = ProgramHeader::default();
    ph.p_type = 0xFFFFFFFF;
    assert_eq!(ph.type_name(), "UNKNOWN");
}

#[test]
fn test_flags_str_rwx() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_W | phdr_flags::PF_X;
    assert_eq!(ph.flags_str(), "RWX");
}

#[test]
fn test_flags_str_rw() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_W;
    assert_eq!(ph.flags_str(), "RW-");
}

#[test]
fn test_flags_str_rx() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_X;
    assert_eq!(ph.flags_str(), "R-X");
}

#[test]
fn test_flags_str_r() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R;
    assert_eq!(ph.flags_str(), "R--");
}

#[test]
fn test_flags_str_wx() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_W | phdr_flags::PF_X;
    assert_eq!(ph.flags_str(), "-WX");
}

#[test]
fn test_flags_str_w() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_W;
    assert_eq!(ph.flags_str(), "-W-");
}

#[test]
fn test_flags_str_x() {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_X;
    assert_eq!(ph.flags_str(), "--X");
}

#[test]
fn test_flags_str_none() {
    let ph = ProgramHeader::default();
    assert_eq!(ph.flags_str(), "---");
}

#[test]
fn test_program_header_clone() {
    let mut ph = ProgramHeader::default();
    ph.p_vaddr = 0x400000;
    ph.p_memsz = 0x1000;
    let cloned = ph;
    assert_eq!(cloned.p_vaddr, 0x400000);
    assert_eq!(cloned.p_memsz, 0x1000);
}

#[test]
fn test_program_header_copy() {
    let mut ph = ProgramHeader::default();
    ph.p_offset = 0x1000;
    let copied: ProgramHeader = ph;
    assert_eq!(copied.p_offset, 0x1000);
    assert_eq!(ph.p_offset, 0x1000);
}

#[test]
fn test_program_header_alignment() {
    assert_eq!(mem::align_of::<ProgramHeader>(), 8);
}

#[test]
fn test_phdr_type_constants() {
    assert_eq!(phdr_type::PT_NULL, 0);
    assert_eq!(phdr_type::PT_LOAD, 1);
    assert_eq!(phdr_type::PT_DYNAMIC, 2);
    assert_eq!(phdr_type::PT_INTERP, 3);
    assert_eq!(phdr_type::PT_NOTE, 4);
    assert_eq!(phdr_type::PT_SHLIB, 5);
    assert_eq!(phdr_type::PT_PHDR, 6);
    assert_eq!(phdr_type::PT_TLS, 7);
    assert_eq!(phdr_type::PT_GNU_EH_FRAME, 0x6474_E550);
    assert_eq!(phdr_type::PT_GNU_STACK, 0x6474_E551);
    assert_eq!(phdr_type::PT_GNU_RELRO, 0x6474_E552);
}

#[test]
fn test_phdr_flags_constants() {
    assert_eq!(phdr_flags::PF_X, 1);
    assert_eq!(phdr_flags::PF_W, 2);
    assert_eq!(phdr_flags::PF_R, 4);
}

#[test]
fn test_program_header_fully_configured() {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_LOAD;
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_X;
    ph.p_offset = 0x1000;
    ph.p_vaddr = 0x401000;
    ph.p_paddr = 0x401000;
    ph.p_filesz = 0x5000;
    ph.p_memsz = 0x6000;
    ph.p_align = 0x1000;

    assert!(ph.is_load());
    assert!(ph.is_readable());
    assert!(!ph.is_writable());
    assert!(ph.is_executable());
    assert_eq!(ph.bss_size(), 0x1000);
    assert_eq!(ph.type_name(), "LOAD");
    assert_eq!(ph.flags_str(), "R-X");
}
