//! ELF Interpreter/PT_INTERP Support for Loader

extern crate alloc;
use alloc::string::{String, ToString};
use crate::elf::errors::ElfError;
use crate::elf::types::ProgramHeader;

/// Information about the interpreter (PT_INTERP) for a loaded ELF image.
#[derive(Debug, Clone)]
pub struct InterpreterInfo {
    /// Path to the interpreter
    pub path: String,
}

impl InterpreterInfo {
    /// Parse interpreter path from ELF data and program header.
    pub fn from_elf(elf_data: &[u8], ph: &ProgramHeader) -> Result<Self, ElfError> {
        let file_offset = ph.p_offset as usize;
        let size = ph.p_filesz as usize;
        if file_offset + size > elf_data.len() {
            return Err(ElfError::InterpreterNotFound);
        }
        let path_bytes = &elf_data[file_offset..file_offset + size];
        let null_pos = path_bytes.iter().position(|&b| b == 0).unwrap_or(path_bytes.len());
        let path_str = core::str::from_utf8(&path_bytes[..null_pos]).map_err(|_| ElfError::InterpreterNotFound)?;
        Ok(InterpreterInfo { path: path_str.into() })
    }
}
