pub mod nonos_auth;
pub mod nonos_manifest;
pub mod nonos_mod_loader;
pub mod nonos_mod_runner;
pub mod nonos_registry;
pub mod nonos_runtime;
pub mod nonos_sandbox;
pub mod nonos_module_loader;

// Re-exports for backward compatibility
pub use nonos_auth as auth;
pub use nonos_manifest as manifest;
pub use nonos_mod_loader as mod_loader;
pub use nonos_mod_runner as mod_runner;
pub use nonos_registry as registry;
pub use nonos_runtime as runtime;
pub use nonos_sandbox as sandbox;

use alloc::{vec::Vec, collections::BTreeMap, string::{String, ToString}};

#[derive(Debug, Clone)]
pub struct LoadedModule {
    pub name: String,
    pub base_address: usize,
    pub size: usize,
    pub hash: [u8; 32],
    pub verified: bool,
}

/// Check if a module is currently active
pub fn is_module_active(module_name: &str) -> bool {
    // TODO: Implement actual module registry check
    false
}

/// Get the message queue for a specific module
pub fn get_module_message_queue(module_name: &str) -> Option<Vec<u8>> {
    // TODO: Implement actual message queue lookup
    None
}

/// Notify a module that a message is ready
pub fn notify_module_message_ready(module_name: &str) {
    // Real IPC notification via kernel message queues
    if let Some(module) = LOADED_MODULES.lock().get(module_name) {
        // Send signal to module's message queue
        unsafe {
            let signal = 1u64;
            core::ptr::write_volatile(
                (module.base_address + module.msg_queue_offset) as *mut u64, 
                signal
            );
        }
    }
}

use spin::Mutex;
static LOADED_MODULES: Mutex<BTreeMap<String, ModuleEntry>> = Mutex::new(BTreeMap::new());

#[derive(Debug, Clone)]
struct ModuleEntry {
    base_address: usize,
    size: usize,
    entry_point: usize,
    msg_queue_offset: usize,
    ref_count: u32,
}

/// Real kernel module enumeration using ELF parsing
pub fn get_loaded_modules() -> Vec<LoadedModule> {
    let mut modules = Vec::new();
    let loaded_modules = LOADED_MODULES.lock();
    
    for (name, entry) in loaded_modules.iter() {
        // Parse ELF headers to get real module info
        let elf_header = unsafe { 
            &*((entry.base_address) as *const ElfHeader) 
        };
        
        if elf_header.e_ident[0] == 0x7f && 
           elf_header.e_ident[1] == b'E' && 
           elf_header.e_ident[2] == b'L' && 
           elf_header.e_ident[3] == b'F' {
            
            modules.push(LoadedModule {
                name: name.clone(),
                base_address: entry.base_address,
                size: entry.size,
                hash: calculate_module_hash_from_elf(entry.base_address, entry.size),
                verified: verify_elf_signature(entry.base_address),
            });
        }
    }
    
    modules
}

#[repr(C)]
struct ElfHeader {
    e_ident: [u8; 16],
    e_type: u16,
    e_machine: u16,
    e_version: u32,
    e_entry: u64,
    e_phoff: u64,
    e_shoff: u64,
    e_flags: u32,
    e_ehsize: u16,
    e_phentsize: u16,
    e_phnum: u16,
    e_shentsize: u16,
    e_shnum: u16,
    e_shstrndx: u16,
}

fn calculate_module_hash_from_elf(base_addr: usize, size: usize) -> [u8; 32] {
    // Hash the actual loaded ELF module
    unsafe {
        let module_data = core::slice::from_raw_parts(base_addr as *const u8, size);
        crate::crypto::nonos_hash::blake3_hash(module_data)
    }
}

fn verify_elf_signature(base_addr: usize) -> bool {
    // Real ELF signature verification
    unsafe {
        let elf_header = &*((base_addr) as *const ElfHeader);
        
        // Check ELF magic
        if elf_header.e_ident[0] != 0x7f || 
           elf_header.e_ident[1] != b'E' ||
           elf_header.e_ident[2] != b'L' ||
           elf_header.e_ident[3] != b'F' {
            return false;
        }
        
        // Check architecture (x86_64)
        if elf_header.e_machine != 0x3e {
            return false;
        }
        
        // Verify digital signature in ELF sections
        verify_elf_digital_signature(base_addr, elf_header)
    }
}

fn verify_elf_digital_signature(base_addr: usize, elf_header: &ElfHeader) -> bool {
    // Real digital signature verification of ELF sections
    unsafe {
        let section_headers = core::slice::from_raw_parts(
            (base_addr + elf_header.e_shoff as usize) as *const ElfSectionHeader,
            elf_header.e_shnum as usize
        );
        
        // Look for .signature section
        for section in section_headers {
            if section.sh_type == 0x70000000 { // Custom signature section type
                let sig_data = core::slice::from_raw_parts(
                    (base_addr + section.sh_offset as usize) as *const u8,
                    section.sh_size as usize
                );
                
                // Verify signature using kernel's trusted keys
                return crate::security::trusted_keys::verify_signature(sig_data);
            }
        }
    }
    false
}

#[repr(C)]
struct ElfSectionHeader {
    sh_name: u32,
    sh_type: u32,
    sh_flags: u64,
    sh_addr: u64,
    sh_offset: u64,
    sh_size: u64,
    sh_link: u32,
    sh_info: u32,
    sh_addralign: u64,
    sh_entsize: u64,
}

/// Real module loading from storage
pub fn load_module_from_disk(module_path: &str) -> Result<(), &'static str> {
    // Real file system access to load module
    let module_data = crate::fs::read_file(module_path)
        .map_err(|_| "Failed to read module file")?;
    
    // Parse ELF and allocate memory
    let (base_addr, size, entry_point) = load_elf_module(&module_data)?;
    
    // Create message queue for module IPC
    let msg_queue_offset = allocate_message_queue(base_addr)?;
    
    // Register module
    let module_name = extract_module_name_from_path(module_path);
    LOADED_MODULES.lock().insert(module_name, ModuleEntry {
        base_address: base_addr,
        size,
        entry_point,
        msg_queue_offset,
        ref_count: 1,
    });
    
    // Call module's init function
    unsafe {
        let init_fn: extern "C" fn() -> i32 = core::mem::transmute(entry_point);
        let result = init_fn();
        if result != 0 {
            return Err("Module initialization failed");
        }
    }
    
    Ok(())
}

fn load_elf_module(elf_data: &[u8]) -> Result<(usize, usize, usize), &'static str> {
    // Real ELF loader implementation
    if elf_data.len() < core::mem::size_of::<ElfHeader>() {
        return Err("Invalid ELF file");
    }
    
    let elf_header = unsafe { &*(elf_data.as_ptr() as *const ElfHeader) };
    
    // Validate ELF header
    if elf_header.e_ident[0] != 0x7f || 
       elf_header.e_ident[1] != b'E' ||
       elf_header.e_ident[2] != b'L' ||
       elf_header.e_ident[3] != b'F' {
        return Err("Not a valid ELF file");
    }
    
    // Calculate total memory needed
    let program_headers = unsafe {
        core::slice::from_raw_parts(
            elf_data.as_ptr().add(elf_header.e_phoff as usize) as *const ElfProgramHeader,
            elf_header.e_phnum as usize
        )
    };
    
    let mut max_addr = 0usize;
    let mut min_addr = usize::MAX;
    
    for ph in program_headers {
        if ph.p_type == 1 { // PT_LOAD
            min_addr = min_addr.min(ph.p_vaddr as usize);
            max_addr = max_addr.max((ph.p_vaddr + ph.p_memsz) as usize);
        }
    }
    
    let total_size = max_addr - min_addr;
    let base_addr = crate::memory::nonos_alloc::allocate_kernel_pages(
        (total_size + 0xfff) / 0x1000
    )?;
    
    // Load program segments
    for ph in program_headers {
        if ph.p_type == 1 { // PT_LOAD
            let dest_addr = base_addr + (ph.p_vaddr as usize - min_addr);
            let file_data = &elf_data[ph.p_offset as usize..(ph.p_offset + ph.p_filesz) as usize];
            
            unsafe {
                core::ptr::copy_nonoverlapping(
                    file_data.as_ptr(),
                    dest_addr.as_mut_ptr(),
                    file_data.len()
                );
                
                // Zero BSS section
                if ph.p_memsz > ph.p_filesz {
                    core::ptr::write_bytes(
                        (dest_addr + file_data.len()).as_mut_ptr::<u8>(),
                        0,
                        (ph.p_memsz - ph.p_filesz) as usize
                    );
                }
            }
        }
    }
    
    let entry_point = base_addr.as_u64() as usize + (elf_header.e_entry as usize - min_addr);
    Ok((base_addr.as_u64() as usize, total_size, entry_point))
}

#[repr(C)]
struct ElfProgramHeader {
    p_type: u32,
    p_flags: u32,
    p_offset: u64,
    p_vaddr: u64,
    p_paddr: u64,
    p_filesz: u64,
    p_memsz: u64,
    p_align: u64,
}

fn allocate_message_queue(base_addr: usize) -> Result<usize, &'static str> {
    // Allocate 4KB for message queue at end of module memory
    let queue_page = crate::memory::nonos_alloc::allocate_kernel_pages(1)?;
    
    // Initialize message queue structure
    unsafe {
        core::ptr::write_bytes(queue_page.as_u64() as *mut u8, 0, 4096);
    }
    
    Ok(queue_page.as_u64() as usize - base_addr)
}

fn extract_module_name_from_path(path: &str) -> String {
    path.split('/').last().unwrap_or("unknown").to_string()
}