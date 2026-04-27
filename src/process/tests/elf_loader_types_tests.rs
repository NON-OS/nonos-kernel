use crate::process::elf_loader::*;
use crate::test::framework::TestResult;

pub fn elf64_header_size() -> TestResult {
    if core::mem::size_of::<Elf64Header>() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf64_program_header_size() -> TestResult {
    if core::mem::size_of::<Elf64ProgramHeader>() != 56 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf64_section_header_size() -> TestResult {
    if core::mem::size_of::<Elf64SectionHeader>() != 64 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf64_symbol_size() -> TestResult {
    if core::mem::size_of::<Elf64Symbol>() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf64_rela_size() -> TestResult {
    if core::mem::size_of::<Elf64Rela>() != 24 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf64_dyn_size() -> TestResult {
    if core::mem::size_of::<Elf64Dyn>() != 16 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf64_rela_symbol_index() -> TestResult {
    let rela = Elf64Rela { r_offset: 0x1000, r_info: (42u64 << 32) | 7, r_addend: -8 };
    if rela.symbol_index() != 42 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf64_rela_relocation_type() -> TestResult {
    let rela = Elf64Rela { r_offset: 0x2000, r_info: (100u64 << 32) | 8, r_addend: 0 };
    if rela.relocation_type() != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_segment_end_addr() -> TestResult {
    let seg = LoadedSegment {
        vaddr: 0x1000,
        memsz: 0x500,
        flags: PF_R | PF_X,
        file_offset: 0,
        filesz: 0x400,
    };
    if seg.end_addr() != 0x1500 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_segment_is_readable() -> TestResult {
    let seg_r = LoadedSegment { vaddr: 0, memsz: 0, flags: PF_R, file_offset: 0, filesz: 0 };
    let seg_w = LoadedSegment { vaddr: 0, memsz: 0, flags: PF_W, file_offset: 0, filesz: 0 };
    if !seg_r.is_readable() {
        return TestResult::Fail;
    }
    if seg_w.is_readable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_segment_is_writable() -> TestResult {
    let seg_w = LoadedSegment { vaddr: 0, memsz: 0, flags: PF_W, file_offset: 0, filesz: 0 };
    let seg_r = LoadedSegment { vaddr: 0, memsz: 0, flags: PF_R, file_offset: 0, filesz: 0 };
    if !seg_w.is_writable() {
        return TestResult::Fail;
    }
    if seg_r.is_writable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_segment_is_executable() -> TestResult {
    let seg_x = LoadedSegment { vaddr: 0, memsz: 0, flags: PF_X, file_offset: 0, filesz: 0 };
    let seg_r = LoadedSegment { vaddr: 0, memsz: 0, flags: PF_R, file_offset: 0, filesz: 0 };
    if !seg_x.is_executable() {
        return TestResult::Fail;
    }
    if seg_r.is_executable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_segment_bss_size() -> TestResult {
    let seg = LoadedSegment {
        vaddr: 0x1000,
        memsz: 0x1000,
        flags: PF_R | PF_W,
        file_offset: 0x100,
        filesz: 0x800,
    };
    if seg.bss_size() != 0x800 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_segment_bss_size_zero() -> TestResult {
    let seg =
        LoadedSegment { vaddr: 0x1000, memsz: 0x1000, flags: PF_R, file_offset: 0, filesz: 0x1000 };
    if seg.bss_size() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_segment_get_file_params() -> TestResult {
    let seg = LoadedSegment {
        vaddr: 0x2000,
        memsz: 0x2000,
        flags: PF_R | PF_X,
        file_offset: 0x1000,
        filesz: 0x1800,
    };
    let (offset, size) = seg.get_file_params();
    if offset != 0x1000 {
        return TestResult::Fail;
    }
    if size != 0x1800 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_segment_clone() -> TestResult {
    let seg1 = LoadedSegment {
        vaddr: 0x3000,
        memsz: 0x500,
        flags: PF_R | PF_W | PF_X,
        file_offset: 0x200,
        filesz: 0x400,
    };
    let seg2 = seg1.clone();
    if seg1.vaddr != seg2.vaddr {
        return TestResult::Fail;
    }
    if seg1.memsz != seg2.memsz {
        return TestResult::Fail;
    }
    if seg1.flags != seg2.flags {
        return TestResult::Fail;
    }
    if seg1.file_offset != seg2.file_offset {
        return TestResult::Fail;
    }
    if seg1.filesz != seg2.filesz {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_elf_memory_size() -> TestResult {
    let elf = LoadedElf {
        entry: 0x401000,
        base_addr: 0x400000,
        phdr_addr: 0x400040,
        phnum: 3,
        phentsize: 56,
        segments: alloc::vec![],
        interp: None,
        exec_stack: false,
        min_addr: 0x400000,
        max_addr: 0x500000,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };
    if elf.memory_size() != 0x100000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_elf_has_tls() -> TestResult {
    let elf_no_tls = LoadedElf {
        entry: 0,
        base_addr: 0,
        phdr_addr: 0,
        phnum: 0,
        phentsize: 0,
        segments: alloc::vec![],
        interp: None,
        exec_stack: false,
        min_addr: 0,
        max_addr: 0,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };
    let elf_with_tls = LoadedElf {
        entry: 0,
        base_addr: 0,
        phdr_addr: 0,
        phnum: 0,
        phentsize: 0,
        segments: alloc::vec![],
        interp: None,
        exec_stack: false,
        min_addr: 0,
        max_addr: 0,
        tls_addr: 0x1000,
        tls_size: 64,
        tls_align: 16,
    };
    if elf_no_tls.has_tls() {
        return TestResult::Fail;
    }
    if !elf_with_tls.has_tls() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_elf_get_tls_config() -> TestResult {
    let elf = LoadedElf {
        entry: 0,
        base_addr: 0,
        phdr_addr: 0,
        phnum: 0,
        phentsize: 0,
        segments: alloc::vec![],
        interp: None,
        exec_stack: false,
        min_addr: 0,
        max_addr: 0,
        tls_addr: 0x2000,
        tls_size: 128,
        tls_align: 32,
    };
    let (addr, size, align) = elf.get_tls_config();
    if addr != 0x2000 {
        return TestResult::Fail;
    }
    if size != 128 {
        return TestResult::Fail;
    }
    if align != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_elf_needs_interp() -> TestResult {
    let elf_no_interp = LoadedElf {
        entry: 0,
        base_addr: 0,
        phdr_addr: 0,
        phnum: 0,
        phentsize: 0,
        segments: alloc::vec![],
        interp: None,
        exec_stack: false,
        min_addr: 0,
        max_addr: 0,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };
    let elf_with_interp = LoadedElf {
        entry: 0,
        base_addr: 0,
        phdr_addr: 0,
        phnum: 0,
        phentsize: 0,
        segments: alloc::vec![],
        interp: Some(alloc::string::String::from("/lib/ld-linux.so.2")),
        exec_stack: false,
        min_addr: 0,
        max_addr: 0,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };
    if elf_no_interp.needs_interp() {
        return TestResult::Fail;
    }
    if !elf_with_interp.needs_interp() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_elf_get_interp() -> TestResult {
    let elf = LoadedElf {
        entry: 0,
        base_addr: 0,
        phdr_addr: 0,
        phnum: 0,
        phentsize: 0,
        segments: alloc::vec![],
        interp: Some(alloc::string::String::from("/lib64/ld-linux-x86-64.so.2")),
        exec_stack: false,
        min_addr: 0,
        max_addr: 0,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };
    if elf.get_interp() != Some("/lib64/ld-linux-x86-64.so.2") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_elf_allows_exec_stack() -> TestResult {
    let elf_no_exec = LoadedElf {
        entry: 0,
        base_addr: 0,
        phdr_addr: 0,
        phnum: 0,
        phentsize: 0,
        segments: alloc::vec![],
        interp: None,
        exec_stack: false,
        min_addr: 0,
        max_addr: 0,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };
    let elf_exec = LoadedElf {
        entry: 0,
        base_addr: 0,
        phdr_addr: 0,
        phnum: 0,
        phentsize: 0,
        segments: alloc::vec![],
        interp: None,
        exec_stack: true,
        min_addr: 0,
        max_addr: 0,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };
    if elf_no_exec.allows_exec_stack() {
        return TestResult::Fail;
    }
    if !elf_exec.allows_exec_stack() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn loaded_elf_get_phdr_info() -> TestResult {
    let elf = LoadedElf {
        entry: 0x401000,
        base_addr: 0x400000,
        phdr_addr: 0x400040,
        phnum: 5,
        phentsize: 56,
        segments: alloc::vec![],
        interp: None,
        exec_stack: false,
        min_addr: 0x400000,
        max_addr: 0x500000,
        tls_addr: 0,
        tls_size: 0,
        tls_align: 0,
    };
    let (addr, num, entsize) = elf.get_phdr_info();
    if addr != 0x400040 {
        return TestResult::Fail;
    }
    if num != 5 {
        return TestResult::Fail;
    }
    if entsize != 56 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf_error_variants() -> TestResult {
    if ElfError::TooSmall != ElfError::TooSmall {
        return TestResult::Fail;
    }
    if ElfError::InvalidMagic != ElfError::InvalidMagic {
        return TestResult::Fail;
    }
    if ElfError::Not64Bit != ElfError::Not64Bit {
        return TestResult::Fail;
    }
    if ElfError::WrongEndian != ElfError::WrongEndian {
        return TestResult::Fail;
    }
    if ElfError::WrongMachine != ElfError::WrongMachine {
        return TestResult::Fail;
    }
    if ElfError::NotExecutable != ElfError::NotExecutable {
        return TestResult::Fail;
    }
    if ElfError::InvalidProgramHeader != ElfError::InvalidProgramHeader {
        return TestResult::Fail;
    }
    if ElfError::InvalidSectionHeader != ElfError::InvalidSectionHeader {
        return TestResult::Fail;
    }
    if ElfError::OverlappingSegments != ElfError::OverlappingSegments {
        return TestResult::Fail;
    }
    if ElfError::InvalidAddress != ElfError::InvalidAddress {
        return TestResult::Fail;
    }
    if ElfError::WXViolation != ElfError::WXViolation {
        return TestResult::Fail;
    }
    if ElfError::AllocationFailed != ElfError::AllocationFailed {
        return TestResult::Fail;
    }
    if ElfError::InvalidAlignment != ElfError::InvalidAlignment {
        return TestResult::Fail;
    }
    if ElfError::RelocationFailed != ElfError::RelocationFailed {
        return TestResult::Fail;
    }
    if ElfError::MissingSection != ElfError::MissingSection {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf_error_not_equal() -> TestResult {
    if ElfError::TooSmall == ElfError::InvalidMagic {
        return TestResult::Fail;
    }
    if ElfError::Not64Bit == ElfError::WrongEndian {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf_error_display() -> TestResult {
    use alloc::string::ToString;
    if ElfError::TooSmall.to_string() != "ELF data too small" {
        return TestResult::Fail;
    }
    if ElfError::InvalidMagic.to_string() != "Invalid ELF magic number" {
        return TestResult::Fail;
    }
    if ElfError::Not64Bit.to_string() != "Not a 64-bit ELF" {
        return TestResult::Fail;
    }
    if ElfError::WrongEndian.to_string() != "Wrong endianness" {
        return TestResult::Fail;
    }
    if ElfError::WrongMachine.to_string() != "Unsupported machine type" {
        return TestResult::Fail;
    }
    if ElfError::NotExecutable.to_string() != "Not an executable" {
        return TestResult::Fail;
    }
    if ElfError::InvalidProgramHeader.to_string() != "Invalid program header" {
        return TestResult::Fail;
    }
    if ElfError::InvalidSectionHeader.to_string() != "Invalid section header" {
        return TestResult::Fail;
    }
    if ElfError::OverlappingSegments.to_string() != "Overlapping segments" {
        return TestResult::Fail;
    }
    if ElfError::InvalidAddress.to_string() != "Invalid address" {
        return TestResult::Fail;
    }
    if ElfError::WXViolation.to_string() != "W^X violation" {
        return TestResult::Fail;
    }
    if ElfError::AllocationFailed.to_string() != "Memory allocation failed" {
        return TestResult::Fail;
    }
    if ElfError::InvalidAlignment.to_string() != "Invalid alignment" {
        return TestResult::Fail;
    }
    if ElfError::RelocationFailed.to_string() != "Relocation failed" {
        return TestResult::Fail;
    }
    if ElfError::MissingSection.to_string() != "Missing required section" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn elf_error_clone() -> TestResult {
    let err1 = ElfError::InvalidMagic;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn pf_flags_defined() -> TestResult {
    if PF_X != 0x1 {
        return TestResult::Fail;
    }
    if PF_W != 0x2 {
        return TestResult::Fail;
    }
    if PF_R != 0x4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub fn pf_flag_combinations() -> TestResult {
    let rx = PF_R | PF_X;
    let rw = PF_R | PF_W;
    let rwx = PF_R | PF_W | PF_X;
    if rx != 0x5 {
        return TestResult::Fail;
    }
    if rw != 0x6 {
        return TestResult::Fail;
    }
    if rwx != 0x7 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
