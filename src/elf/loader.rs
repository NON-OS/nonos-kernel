//! ELF Loader with Dynamic Linking and ASLR

use alloc::{vec::Vec, string::{String, ToString}, collections::BTreeMap};
use core::{mem, ptr};
use x86_64::{VirtAddr, structures::paging::PageTableFlags};
use crate::memory::{frame_alloc, virtual_memory};
use crate::elf::types::*;
use crate::elf::errors::ElfError;
use crate::elf::aslr::AslrManager;
use crate::elf::reloc::process_relocations;
use crate::elf::tls::TlsInfo;

/// Loaded ELF image information
#[derive(Debug)]
pub struct ElfImage {
    pub base_addr: VirtAddr,
    pub entry_point: VirtAddr,
    pub size: usize,
    pub segments: Vec<LoadedSegment>,
    pub dynamic_info: Option<DynamicInfo>,
    pub tls_info: Option<TlsInfo>,
    pub interpreter: Option<String>,
}

/// Loaded segment information
#[derive(Debug)]
pub struct LoadedSegment {
    pub vaddr: VirtAddr,
    pub size: usize,
    pub flags: PageTableFlags,
    pub segment_type: u32,
}

/// Dynamic linking information
#[derive(Debug)]
pub struct DynamicInfo {
    pub needed_libraries: Vec<String>,
    pub symbol_table: Option<VirtAddr>,
    pub string_table: Option<VirtAddr>,
    pub string_table_size: usize,
    pub rela_table: Option<VirtAddr>,
    pub rela_size: usize,
    pub plt_relocations: Option<VirtAddr>,
    pub plt_rela_size: usize,
    pub init_function: Option<VirtAddr>,
    pub fini_function: Option<VirtAddr>,
}

/// Advanced ELF loader with dynamic linking, ASLR, TLS, and interpreter support
pub struct ElfLoader {
    aslr_manager: AslrManager,
    loaded_libraries: BTreeMap<String, ElfImage>,
    symbol_cache: BTreeMap<String, VirtAddr>,
}

impl ElfLoader {
    /// Create new ELF loader
    pub fn new() -> Self {
        ElfLoader {
            aslr_manager: AslrManager::new(),
            loaded_libraries: BTreeMap::new(),
            symbol_cache: BTreeMap::new(),
        }
    }

    /// Load ELF executable from memory
    pub fn load_executable(&mut self, elf_data: &[u8]) -> Result<ElfImage, ElfError> {
        // Parse ELF header
        let header = self.parse_elf_header(elf_data)?;

        // Validate ELF
        self.validate_elf(&header)?;

        // Parse program headers
        let program_headers = self.parse_program_headers(elf_data, &header)?;

        // Calculate base address with ASLR
        let base_addr = if header.e_type == 3 /* DYN */ {
            // PIE executable
            let preferred_base = 0x400000u64;
            VirtAddr::new(self.aslr_manager.randomize_base(preferred_base))
        } else {
            // Static executable
            VirtAddr::new(0x400000u64)
        };

        // Load segments
        let mut loaded_segments = Vec::new();
        let mut dynamic_info = None;
        let mut tls_info = None;
        let mut interpreter = None;

        for ph in &program_headers {
            match ph.p_type {
                1 /* PT_LOAD */ => {
                    let segment = self.load_segment(elf_data, ph, base_addr)?;
                    loaded_segments.push(segment);
                },
                2 /* PT_DYNAMIC */ => {
                    dynamic_info = Some(self.parse_dynamic_section(elf_data, ph, base_addr)?);
                },
                7 /* PT_TLS */ => {
                    tls_info = Some(self.parse_tls_section(ph, base_addr)?);
                },
                3 /* PT_INTERP */ => {
                    interpreter = Some(self.parse_interpreter(elf_data, ph)?);
                },
                _ => {} // Ignore other types
            }
        }

        // Entry point
        let entry_point = if header.e_type == 3 /* DYN */ {
            base_addr + header.e_entry
        } else {
            VirtAddr::new(header.e_entry)
        };

        // Total image size
        let total_size = loaded_segments.iter().map(|seg| seg.size).sum();

        let image = ElfImage {
            base_addr,
            entry_point,
            size: total_size,
            segments: loaded_segments,
            dynamic_info,
            tls_info,
            interpreter,
        };

        // Relocation
        if let Some(ref dyn_info) = image.dynamic_info {
            let mut rela_entries = Vec::new();

            if let Some(rela_addr) = dyn_info.rela_table {
                let entry_count = dyn_info.rela_size / mem::size_of::<RelaEntry>();
                let rela_ptr = rela_addr.as_u64() as *const RelaEntry;
                unsafe {
                    for i in 0..entry_count {
                        rela_entries.push(ptr::read(rela_ptr.add(i)));
                    }
                }
            }
            if !rela_entries.is_empty() {
                process_relocations(&image, &rela_entries)?;
            }
        }

        Ok(image)
    }

    /// Parse ELF header
    fn parse_elf_header(&self, elf_data: &[u8]) -> Result<ElfHeader, ElfError> {
        if elf_data.len() < mem::size_of::<ElfHeader>() {
            return Err(ElfError::FileTooSmall);
        }
        unsafe {
            let header_ptr = elf_data.as_ptr() as *const ElfHeader;
            Ok(ptr::read(header_ptr))
        }
    }

    /// Validate ELF header
    fn validate_elf(&self, header: &ElfHeader) -> Result<(), ElfError> {
        if &header.ident[0..4] != b"\x7FELF" {
            return Err(ElfError::InvalidMagic);
        }
        if header.ident[4] != 2 {
            return Err(ElfError::InvalidClass);
        }
        if header.ident[5] != 1 {
            return Err(ElfError::InvalidEndian);
        }
        if header.ident[6] != 1 {
            return Err(ElfError::InvalidVersion);
        }
        if header.e_machine != 0x3E {
            return Err(ElfError::InvalidMachine);
        }
        if header.e_type != 2 && header.e_type != 3 {
            return Err(ElfError::InvalidType);
        }
        Ok(())
    }

    /// Parse program headers
    fn parse_program_headers(&self, elf_data: &[u8], header: &ElfHeader) -> Result<Vec<ProgramHeader>, ElfError> {
        let ph_offset = header.e_phoff as usize;
        let ph_size = header.e_phentsize as usize;
        let ph_count = header.e_phnum as usize;

        if ph_offset + (ph_size * ph_count) > elf_data.len() {
            return Err(ElfError::ProgramHeadersOutOfBounds);
        }

        let mut program_headers = Vec::with_capacity(ph_count);
        for i in 0..ph_count {
            let offset = ph_offset + (i * ph_size);
            unsafe {
                let ph_ptr = elf_data[offset..].as_ptr() as *const ProgramHeader;
                program_headers.push(ptr::read(ph_ptr));
            }
        }
        Ok(program_headers)
    }

    /// Load a single segment
    fn load_segment(&self, elf_data: &[u8], ph: &ProgramHeader, base_addr: VirtAddr) -> Result<LoadedSegment, ElfError> {
        let vaddr = base_addr + ph.p_vaddr;
        let size = ph.p_memsz as usize;
        let file_size = ph.p_filesz as usize;

        // Convert ELF flags to page table flags
        let mut flags = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
        if ph.p_flags & 0x2 != 0 { // PF_W
            flags |= PageTableFlags::WRITABLE;
        }
        if ph.p_flags & 0x1 == 0 { // !PF_X
            flags |= PageTableFlags::NO_EXECUTE;
        }

        // Allocate and map memory
        let pages_needed = (size + 0xFFF) >> 12;
        for i in 0..pages_needed {
            if let Some(frame) = frame_alloc::allocate_frame() {
                let page_vaddr = vaddr + (i * 4096);
                // Convert PageTableFlags to VmProtection
                let protection = if flags.contains(x86_64::structures::paging::PageTableFlags::WRITABLE) {
                    if flags.contains(x86_64::structures::paging::PageTableFlags::NO_EXECUTE) {
                        crate::memory::virtual_memory::VmProtection::ReadWrite
                    } else {
                        crate::memory::virtual_memory::VmProtection::ReadWriteExecute
                    }
                } else if flags.contains(x86_64::structures::paging::PageTableFlags::NO_EXECUTE) {
                    crate::memory::virtual_memory::VmProtection::Read
                } else {
                    crate::memory::virtual_memory::VmProtection::ReadExecute
                };
                virtual_memory::map_memory_range(
                    page_vaddr,
                    4096,
                    protection,
                    crate::memory::virtual_memory::VmType::File
                )?;
            } else {
                return Err(ElfError::MemoryAllocationFailed);
            }
        }

        // Copy segment data
        if file_size > 0 {
            let file_offset = ph.p_offset as usize;
            if file_offset + file_size > elf_data.len() {
                return Err(ElfError::SegmentDataOutOfBounds);
            }
            unsafe {
                let src = elf_data[file_offset..file_offset + file_size].as_ptr();
                let dst = vaddr.as_mut_ptr::<u8>();
                ptr::copy_nonoverlapping(src, dst, file_size);

                // Zero remaining memory (BSS)
                if size > file_size {
                    ptr::write_bytes(dst.add(file_size), 0, size - file_size);
                }
            }
        } else if size > 0 {
            unsafe {
                let dst = vaddr.as_mut_ptr::<u8>();
                ptr::write_bytes(dst, 0, size);
            }
        }

        Ok(LoadedSegment {
            vaddr,
            size,
            flags,
            segment_type: ph.p_type,
        })
    }

    /// Parse dynamic section
    fn parse_dynamic_section(&self, elf_data: &[u8], ph: &ProgramHeader, base_addr: VirtAddr) -> Result<DynamicInfo, ElfError> {
        let mut dynamic_info = DynamicInfo {
            needed_libraries: Vec::new(),
            symbol_table: None,
            string_table: None,
            string_table_size: 0,
            rela_table: None,
            rela_size: 0,
            plt_relocations: None,
            plt_rela_size: 0,
            init_function: None,
            fini_function: None,
        };

        let file_offset = ph.p_offset as usize;
        let entry_count = (ph.p_filesz as usize) / mem::size_of::<DynamicEntry>();

        for i in 0..entry_count {
            let entry_offset = file_offset + (i * mem::size_of::<DynamicEntry>());
            if entry_offset + mem::size_of::<DynamicEntry>() > elf_data.len() {
                break;
            }
            unsafe {
                let entry_ptr = elf_data[entry_offset..].as_ptr() as *const DynamicEntry;
                let entry = ptr::read(entry_ptr);

                match entry.d_tag {
                    0 => break, // DT_NULL
                    1 => {},    // DT_NEEDED (can be filled after string table found)
                    5 => {      // DT_STRTAB
                        dynamic_info.string_table = Some(base_addr + entry.value);
                    },
                    10 => {     // DT_STRSZ
                        dynamic_info.string_table_size = entry.value as usize;
                    },
                    6 => {      // DT_SYMTAB
                        dynamic_info.symbol_table = Some(base_addr + entry.value);
                    },
                    7 => {      // DT_RELA
                        dynamic_info.rela_table = Some(base_addr + entry.value);
                    },
                    8 => {      // DT_RELASZ
                        dynamic_info.rela_size = entry.value as usize;
                    },
                    23 => {     // DT_JMPREL
                        dynamic_info.plt_relocations = Some(base_addr + entry.value);
                    },
                    2 => {      // DT_PLTRELSZ
                        dynamic_info.plt_rela_size = entry.value as usize;
                    },
                    12 => {     // DT_INIT
                        dynamic_info.init_function = Some(base_addr + entry.value);
                    },
                    13 => {     // DT_FINI
                        dynamic_info.fini_function = Some(base_addr + entry.value);
                    },
                    _ => {}
                }
            }
        }
        Ok(dynamic_info)
    }

    /// Parse TLS section
    fn parse_tls_section(&self, ph: &ProgramHeader, base_addr: VirtAddr) -> Result<TlsInfo, ElfError> {
        Ok(TlsInfo {
            template_addr: base_addr + ph.p_vaddr,
            template_size: ph.p_filesz as usize,
            memory_size: ph.p_memsz as usize,
            alignment: ph.p_align as usize,
        })
    }

    /// Parse interpreter path
    fn parse_interpreter(&self, elf_data: &[u8], ph: &ProgramHeader) -> Result<String, ElfError> {
        let file_offset = ph.p_offset as usize;
        let size = ph.p_filesz as usize;
        if file_offset + size > elf_data.len() {
            return Err(ElfError::InterpreterNotFound);
        }
        let path_bytes = &elf_data[file_offset..file_offset + size];
        let null_pos = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
        let path_str = core::str::from_utf8(&path_bytes[..null_pos]).map_err(|_| ElfError::InterpreterNotFound)?;
        Ok(path_str.into())
    }
}

/// Global ELF loader instance
static mut ELF_LOADER: Option<ElfLoader> = None;

/// Initialize ELF loader
pub fn init_elf_loader() {
    unsafe {
        ELF_LOADER = Some(ElfLoader::new());
    }
}

/// Get ELF loader
pub fn get_elf_loader() -> Option<&'static mut ElfLoader> {
    unsafe { ELF_LOADER.as_mut() }
}

/// Load ELF executable
pub fn load_elf_executable(elf_data: &[u8]) -> Result<ElfImage, ElfError> {
    if let Some(loader) = get_elf_loader() {
        loader.load_executable(elf_data)
    } else {
        Err(ElfError::Other("ELF loader not initialized"))
    }
}
