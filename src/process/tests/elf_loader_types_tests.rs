use crate::process::elf_loader::*;

#[test]
fn elf64_header_size() {
    assert_eq!(core::mem::size_of::<Elf64Header>(), 64);
}

#[test]
fn elf64_program_header_size() {
    assert_eq!(core::mem::size_of::<Elf64ProgramHeader>(), 56);
}

#[test]
fn elf64_section_header_size() {
    assert_eq!(core::mem::size_of::<Elf64SectionHeader>(), 64);
}

#[test]
fn elf64_symbol_size() {
    assert_eq!(core::mem::size_of::<Elf64Symbol>(), 24);
}

#[test]
fn elf64_rela_size() {
    assert_eq!(core::mem::size_of::<Elf64Rela>(), 24);
}

#[test]
fn elf64_dyn_size() {
    assert_eq!(core::mem::size_of::<Elf64Dyn>(), 16);
}

#[test]
fn elf64_rela_symbol_index() {
    let rela = Elf64Rela {
        r_offset: 0x1000,
        r_info: (42u64 << 32) | 7,
        r_addend: -8,
    };
    assert_eq!(rela.symbol_index(), 42);
}

#[test]
fn elf64_rela_relocation_type() {
    let rela = Elf64Rela {
        r_offset: 0x2000,
        r_info: (100u64 << 32) | 8,
        r_addend: 0,
    };
    assert_eq!(rela.relocation_type(), 8);
}

#[test]
fn loaded_segment_end_addr() {
    let seg = LoadedSegment {
        vaddr: 0x1000,
        memsz: 0x500,
        flags: PF_R | PF_X,
        file_offset: 0,
        filesz: 0x400,
    };
    assert_eq!(seg.end_addr(), 0x1500);
}

#[test]
fn loaded_segment_is_readable() {
    let seg_r = LoadedSegment {
        vaddr: 0, memsz: 0, flags: PF_R, file_offset: 0, filesz: 0
    };
    let seg_w = LoadedSegment {
        vaddr: 0, memsz: 0, flags: PF_W, file_offset: 0, filesz: 0
    };
    assert!(seg_r.is_readable());
    assert!(!seg_w.is_readable());
}

#[test]
fn loaded_segment_is_writable() {
    let seg_w = LoadedSegment {
        vaddr: 0, memsz: 0, flags: PF_W, file_offset: 0, filesz: 0
    };
    let seg_r = LoadedSegment {
        vaddr: 0, memsz: 0, flags: PF_R, file_offset: 0, filesz: 0
    };
    assert!(seg_w.is_writable());
    assert!(!seg_r.is_writable());
}

#[test]
fn loaded_segment_is_executable() {
    let seg_x = LoadedSegment {
        vaddr: 0, memsz: 0, flags: PF_X, file_offset: 0, filesz: 0
    };
    let seg_r = LoadedSegment {
        vaddr: 0, memsz: 0, flags: PF_R, file_offset: 0, filesz: 0
    };
    assert!(seg_x.is_executable());
    assert!(!seg_r.is_executable());
}

#[test]
fn loaded_segment_bss_size() {
    let seg = LoadedSegment {
        vaddr: 0x1000,
        memsz: 0x1000,
        flags: PF_R | PF_W,
        file_offset: 0x100,
        filesz: 0x800,
    };
    assert_eq!(seg.bss_size(), 0x800);
}

#[test]
fn loaded_segment_bss_size_zero() {
    let seg = LoadedSegment {
        vaddr: 0x1000,
        memsz: 0x1000,
        flags: PF_R,
        file_offset: 0,
        filesz: 0x1000,
    };
    assert_eq!(seg.bss_size(), 0);
}

#[test]
fn loaded_segment_get_file_params() {
    let seg = LoadedSegment {
        vaddr: 0x2000,
        memsz: 0x2000,
        flags: PF_R | PF_X,
        file_offset: 0x1000,
        filesz: 0x1800,
    };
    let (offset, size) = seg.get_file_params();
    assert_eq!(offset, 0x1000);
    assert_eq!(size, 0x1800);
}

#[test]
fn loaded_segment_clone() {
    let seg1 = LoadedSegment {
        vaddr: 0x3000,
        memsz: 0x500,
        flags: PF_R | PF_W | PF_X,
        file_offset: 0x200,
        filesz: 0x400,
    };
    let seg2 = seg1.clone();
    assert_eq!(seg1.vaddr, seg2.vaddr);
    assert_eq!(seg1.memsz, seg2.memsz);
    assert_eq!(seg1.flags, seg2.flags);
    assert_eq!(seg1.file_offset, seg2.file_offset);
    assert_eq!(seg1.filesz, seg2.filesz);
}

#[test]
fn loaded_elf_memory_size() {
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
    assert_eq!(elf.memory_size(), 0x100000);
}

#[test]
fn loaded_elf_has_tls() {
    let elf_no_tls = LoadedElf {
        entry: 0, base_addr: 0, phdr_addr: 0, phnum: 0, phentsize: 0,
        segments: alloc::vec![], interp: None, exec_stack: false,
        min_addr: 0, max_addr: 0, tls_addr: 0, tls_size: 0, tls_align: 0,
    };
    let elf_with_tls = LoadedElf {
        entry: 0, base_addr: 0, phdr_addr: 0, phnum: 0, phentsize: 0,
        segments: alloc::vec![], interp: None, exec_stack: false,
        min_addr: 0, max_addr: 0, tls_addr: 0x1000, tls_size: 64, tls_align: 16,
    };
    assert!(!elf_no_tls.has_tls());
    assert!(elf_with_tls.has_tls());
}

#[test]
fn loaded_elf_get_tls_config() {
    let elf = LoadedElf {
        entry: 0, base_addr: 0, phdr_addr: 0, phnum: 0, phentsize: 0,
        segments: alloc::vec![], interp: None, exec_stack: false,
        min_addr: 0, max_addr: 0, tls_addr: 0x2000, tls_size: 128, tls_align: 32,
    };
    let (addr, size, align) = elf.get_tls_config();
    assert_eq!(addr, 0x2000);
    assert_eq!(size, 128);
    assert_eq!(align, 32);
}

#[test]
fn loaded_elf_needs_interp() {
    let elf_no_interp = LoadedElf {
        entry: 0, base_addr: 0, phdr_addr: 0, phnum: 0, phentsize: 0,
        segments: alloc::vec![], interp: None, exec_stack: false,
        min_addr: 0, max_addr: 0, tls_addr: 0, tls_size: 0, tls_align: 0,
    };
    let elf_with_interp = LoadedElf {
        entry: 0, base_addr: 0, phdr_addr: 0, phnum: 0, phentsize: 0,
        segments: alloc::vec![], interp: Some(alloc::string::String::from("/lib/ld-linux.so.2")),
        exec_stack: false, min_addr: 0, max_addr: 0, tls_addr: 0, tls_size: 0, tls_align: 0,
    };
    assert!(!elf_no_interp.needs_interp());
    assert!(elf_with_interp.needs_interp());
}

#[test]
fn loaded_elf_get_interp() {
    let elf = LoadedElf {
        entry: 0, base_addr: 0, phdr_addr: 0, phnum: 0, phentsize: 0,
        segments: alloc::vec![], interp: Some(alloc::string::String::from("/lib64/ld-linux-x86-64.so.2")),
        exec_stack: false, min_addr: 0, max_addr: 0, tls_addr: 0, tls_size: 0, tls_align: 0,
    };
    assert_eq!(elf.get_interp(), Some("/lib64/ld-linux-x86-64.so.2"));
}

#[test]
fn loaded_elf_allows_exec_stack() {
    let elf_no_exec = LoadedElf {
        entry: 0, base_addr: 0, phdr_addr: 0, phnum: 0, phentsize: 0,
        segments: alloc::vec![], interp: None, exec_stack: false,
        min_addr: 0, max_addr: 0, tls_addr: 0, tls_size: 0, tls_align: 0,
    };
    let elf_exec = LoadedElf {
        entry: 0, base_addr: 0, phdr_addr: 0, phnum: 0, phentsize: 0,
        segments: alloc::vec![], interp: None, exec_stack: true,
        min_addr: 0, max_addr: 0, tls_addr: 0, tls_size: 0, tls_align: 0,
    };
    assert!(!elf_no_exec.allows_exec_stack());
    assert!(elf_exec.allows_exec_stack());
}

#[test]
fn loaded_elf_get_phdr_info() {
    let elf = LoadedElf {
        entry: 0x401000, base_addr: 0x400000, phdr_addr: 0x400040, phnum: 5, phentsize: 56,
        segments: alloc::vec![], interp: None, exec_stack: false,
        min_addr: 0x400000, max_addr: 0x500000, tls_addr: 0, tls_size: 0, tls_align: 0,
    };
    let (addr, num, entsize) = elf.get_phdr_info();
    assert_eq!(addr, 0x400040);
    assert_eq!(num, 5);
    assert_eq!(entsize, 56);
}

#[test]
fn elf_error_variants() {
    assert_eq!(ElfError::TooSmall, ElfError::TooSmall);
    assert_eq!(ElfError::InvalidMagic, ElfError::InvalidMagic);
    assert_eq!(ElfError::Not64Bit, ElfError::Not64Bit);
    assert_eq!(ElfError::WrongEndian, ElfError::WrongEndian);
    assert_eq!(ElfError::WrongMachine, ElfError::WrongMachine);
    assert_eq!(ElfError::NotExecutable, ElfError::NotExecutable);
    assert_eq!(ElfError::InvalidProgramHeader, ElfError::InvalidProgramHeader);
    assert_eq!(ElfError::InvalidSectionHeader, ElfError::InvalidSectionHeader);
    assert_eq!(ElfError::OverlappingSegments, ElfError::OverlappingSegments);
    assert_eq!(ElfError::InvalidAddress, ElfError::InvalidAddress);
    assert_eq!(ElfError::WXViolation, ElfError::WXViolation);
    assert_eq!(ElfError::AllocationFailed, ElfError::AllocationFailed);
    assert_eq!(ElfError::InvalidAlignment, ElfError::InvalidAlignment);
    assert_eq!(ElfError::RelocationFailed, ElfError::RelocationFailed);
    assert_eq!(ElfError::MissingSection, ElfError::MissingSection);
}

#[test]
fn elf_error_not_equal() {
    assert_ne!(ElfError::TooSmall, ElfError::InvalidMagic);
    assert_ne!(ElfError::Not64Bit, ElfError::WrongEndian);
}

#[test]
fn elf_error_display() {
    use alloc::string::ToString;
    assert_eq!(ElfError::TooSmall.to_string(), "ELF data too small");
    assert_eq!(ElfError::InvalidMagic.to_string(), "Invalid ELF magic number");
    assert_eq!(ElfError::Not64Bit.to_string(), "Not a 64-bit ELF");
    assert_eq!(ElfError::WrongEndian.to_string(), "Wrong endianness");
    assert_eq!(ElfError::WrongMachine.to_string(), "Unsupported machine type");
    assert_eq!(ElfError::NotExecutable.to_string(), "Not an executable");
    assert_eq!(ElfError::InvalidProgramHeader.to_string(), "Invalid program header");
    assert_eq!(ElfError::InvalidSectionHeader.to_string(), "Invalid section header");
    assert_eq!(ElfError::OverlappingSegments.to_string(), "Overlapping segments");
    assert_eq!(ElfError::InvalidAddress.to_string(), "Invalid address");
    assert_eq!(ElfError::WXViolation.to_string(), "W^X violation");
    assert_eq!(ElfError::AllocationFailed.to_string(), "Memory allocation failed");
    assert_eq!(ElfError::InvalidAlignment.to_string(), "Invalid alignment");
    assert_eq!(ElfError::RelocationFailed.to_string(), "Relocation failed");
    assert_eq!(ElfError::MissingSection.to_string(), "Missing required section");
}

#[test]
fn elf_error_clone() {
    let err1 = ElfError::InvalidMagic;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn pf_flags_defined() {
    assert_eq!(PF_X, 0x1);
    assert_eq!(PF_W, 0x2);
    assert_eq!(PF_R, 0x4);
}

#[test]
fn pf_flag_combinations() {
    let rx = PF_R | PF_X;
    let rw = PF_R | PF_W;
    let rwx = PF_R | PF_W | PF_X;
    assert_eq!(rx, 0x5);
    assert_eq!(rw, 0x6);
    assert_eq!(rwx, 0x7);
}
