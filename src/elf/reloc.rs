//! ELF Relocation Logic for NØNOS Kernel

use x86_64::VirtAddr;
use crate::elf::types::RelaEntry;
use crate::elf::loader::ElfImage;
use crate::elf::errors::ElfError;

/// Supported x86_64 relocation types 
const R_X86_64_RELATIVE: u32 = 8;
const R_X86_64_64: u32 = 1;
const R_X86_64_JUMP_SLOT: u32 = 7;

/// Apply relocations to image memory.
pub fn process_relocations(image: &ElfImage, rela_entries: &[RelaEntry]) -> Result<(), ElfError> {
    for rela in rela_entries {
        let reloc_type = (rela.r_info & 0xFFFFFFFF) as u32;
        // let symbol_index = (rela.r_info >> 32) as u32; // Use for symbol-based relocations

        let target_addr_u64 = image.base_addr.as_u64().wrapping_add(rela.r_offset);
        let target_ptr = target_addr_u64 as *mut u64;

        // Safety: assumes validated segment mapping and sizes.
        unsafe {
            match reloc_type {
                R_X86_64_RELATIVE => {
                    // Base address + addend
                    *target_ptr = image.base_addr.as_u64().wrapping_add(rela.r_addend as u64);
                }
                R_X86_64_64 => {
                    // Symbol value + addend 
                    *target_ptr = rela.r_addend as u64;
                }
                R_X86_64_JUMP_SLOT => {
                    // PLT relocation (full symbol resolution can be added here)
                    *target_ptr = rela.r_addend as u64;
                }
                _ => {
                    // fail on unsupported types
                    return Err(ElfError::RelocationFailed);
                }
            }
        }
    }
    Ok(())
}
