use crate::elf::types::{phdr_flags, phdr_type, ProgramHeader};
use crate::test::framework::TestResult;
use core::mem;

pub(crate) fn test_program_header_size() -> TestResult {
    if mem::size_of::<ProgramHeader>() != ProgramHeader::SIZE {
        return TestResult::Fail;
    }
    if ProgramHeader::SIZE != 56 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_program_header_default() -> TestResult {
    let ph = ProgramHeader::default();
    if ph.p_type != 0 {
        return TestResult::Fail;
    }
    if ph.p_flags != 0 {
        return TestResult::Fail;
    }
    if ph.p_offset != 0 {
        return TestResult::Fail;
    }
    if ph.p_vaddr != 0 {
        return TestResult::Fail;
    }
    if ph.p_paddr != 0 {
        return TestResult::Fail;
    }
    if ph.p_filesz != 0 {
        return TestResult::Fail;
    }
    if ph.p_memsz != 0 {
        return TestResult::Fail;
    }
    if ph.p_align != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_load_true() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_LOAD;
    if !ph.is_load() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_load_false_null() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_NULL;
    if ph.is_load() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_load_false_dynamic() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_DYNAMIC;
    if ph.is_load() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_load_false_interp() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_INTERP;
    if ph.is_load() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_readable_true() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R;
    if !ph.is_readable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_readable_false() -> TestResult {
    let ph = ProgramHeader::default();
    if ph.is_readable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_readable_with_other_flags() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_W | phdr_flags::PF_X;
    if !ph.is_readable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_writable_true() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_W;
    if !ph.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_writable_false() -> TestResult {
    let ph = ProgramHeader::default();
    if ph.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_writable_with_read() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_W;
    if !ph.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_true() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_X;
    if !ph.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_false() -> TestResult {
    let ph = ProgramHeader::default();
    if ph.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_executable_with_read() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_X;
    if !ph.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bss_size_no_bss() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0x1000;
    ph.p_memsz = 0x1000;
    if ph.bss_size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bss_size_with_bss() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0x1000;
    ph.p_memsz = 0x2000;
    if ph.bss_size() != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bss_size_large_bss() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0x100;
    ph.p_memsz = 0x10000;
    if ph.bss_size() != 0xFF00 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bss_size_zero_filesz() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0;
    ph.p_memsz = 0x1000;
    if ph.bss_size() != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bss_size_saturating() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_filesz = 0x2000;
    ph.p_memsz = 0x1000;
    if ph.bss_size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_null() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_NULL;
    if ph.type_name() != "NULL" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_load() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_LOAD;
    if ph.type_name() != "LOAD" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_dynamic() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_DYNAMIC;
    if ph.type_name() != "DYNAMIC" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_interp() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_INTERP;
    if ph.type_name() != "INTERP" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_note() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_NOTE;
    if ph.type_name() != "NOTE" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_phdr() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_PHDR;
    if ph.type_name() != "PHDR" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_tls() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_TLS;
    if ph.type_name() != "TLS" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_gnu_stack() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_GNU_STACK;
    if ph.type_name() != "GNU_STACK" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_gnu_relro() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_GNU_RELRO;
    if ph.type_name() != "GNU_RELRO" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_type_name_unknown() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = 0xFFFFFFFF;
    if ph.type_name() != "UNKNOWN" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_str_rwx() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_W | phdr_flags::PF_X;
    if ph.flags_str() != "RWX" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_str_rw() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_W;
    if ph.flags_str() != "RW-" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_str_rx() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_X;
    if ph.flags_str() != "R-X" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_str_r() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_R;
    if ph.flags_str() != "R--" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_str_wx() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_W | phdr_flags::PF_X;
    if ph.flags_str() != "-WX" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_str_w() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_W;
    if ph.flags_str() != "-W-" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_str_x() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_flags = phdr_flags::PF_X;
    if ph.flags_str() != "--X" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flags_str_none() -> TestResult {
    let ph = ProgramHeader::default();
    if ph.flags_str() != "---" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_program_header_clone() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_vaddr = 0x400000;
    ph.p_memsz = 0x1000;
    let cloned = ph;
    if cloned.p_vaddr != 0x400000 {
        return TestResult::Fail;
    }
    if cloned.p_memsz != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_program_header_copy() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_offset = 0x1000;
    let copied: ProgramHeader = ph;
    if copied.p_offset != 0x1000 {
        return TestResult::Fail;
    }
    if ph.p_offset != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_program_header_alignment() -> TestResult {
    if mem::align_of::<ProgramHeader>() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_phdr_type_constants() -> TestResult {
    if phdr_type::PT_NULL != 0 {
        return TestResult::Fail;
    }
    if phdr_type::PT_LOAD != 1 {
        return TestResult::Fail;
    }
    if phdr_type::PT_DYNAMIC != 2 {
        return TestResult::Fail;
    }
    if phdr_type::PT_INTERP != 3 {
        return TestResult::Fail;
    }
    if phdr_type::PT_NOTE != 4 {
        return TestResult::Fail;
    }
    if phdr_type::PT_SHLIB != 5 {
        return TestResult::Fail;
    }
    if phdr_type::PT_PHDR != 6 {
        return TestResult::Fail;
    }
    if phdr_type::PT_TLS != 7 {
        return TestResult::Fail;
    }
    if phdr_type::PT_GNU_EH_FRAME != 0x6474_E550 {
        return TestResult::Fail;
    }
    if phdr_type::PT_GNU_STACK != 0x6474_E551 {
        return TestResult::Fail;
    }
    if phdr_type::PT_GNU_RELRO != 0x6474_E552 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_phdr_flags_constants() -> TestResult {
    if phdr_flags::PF_X != 1 {
        return TestResult::Fail;
    }
    if phdr_flags::PF_W != 2 {
        return TestResult::Fail;
    }
    if phdr_flags::PF_R != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_program_header_fully_configured() -> TestResult {
    let mut ph = ProgramHeader::default();
    ph.p_type = phdr_type::PT_LOAD;
    ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_X;
    ph.p_offset = 0x1000;
    ph.p_vaddr = 0x401000;
    ph.p_paddr = 0x401000;
    ph.p_filesz = 0x5000;
    ph.p_memsz = 0x6000;
    ph.p_align = 0x1000;

    if !ph.is_load() {
        return TestResult::Fail;
    }
    if !ph.is_readable() {
        return TestResult::Fail;
    }
    if ph.is_writable() {
        return TestResult::Fail;
    }
    if !ph.is_executable() {
        return TestResult::Fail;
    }
    if ph.bss_size() != 0x1000 {
        return TestResult::Fail;
    }
    if ph.type_name() != "LOAD" {
        return TestResult::Fail;
    }
    if ph.flags_str() != "R-X" {
        return TestResult::Fail;
    }
    TestResult::Pass
}
