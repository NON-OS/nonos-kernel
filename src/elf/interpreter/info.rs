// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;

use alloc::string::String;

use crate::elf::errors::ElfError;
use crate::elf::types::ProgramHeader;

pub const MAX_INTERP_PATH_LEN: usize = 4096;
pub const NONOS_INTERP: &str = "/lib/ld-nonos.so.1";

pub mod known_interp {
    pub const GLIBC_LD: &str = "ld-linux";
    pub const MUSL_LD: &str = "ld-musl";
    pub const GENERIC_LD: &str = "ld.so";
}

#[derive(Debug, Clone)]
pub struct InterpreterInfo {
    pub path: String,
}

impl InterpreterInfo {
    pub fn new(path: String) -> Self {
        Self { path }
    }

    pub fn from_elf(elf_data: &[u8], ph: &ProgramHeader) -> Result<Self, ElfError> {
        let file_offset = ph.p_offset as usize;
        let size = ph.p_filesz as usize;

        if size == 0 {
            return Err(ElfError::InterpreterNotFound);
        }
        if size > MAX_INTERP_PATH_LEN {
            return Err(ElfError::InterpreterNotFound);
        }
        if file_offset.checked_add(size).is_none() {
            return Err(ElfError::InterpreterNotFound);
        }
        if file_offset + size > elf_data.len() {
            return Err(ElfError::InterpreterNotFound);
        }

        let path_bytes = &elf_data[file_offset..file_offset + size];

        let null_pos = path_bytes
            .iter()
            .position(|&b| b == 0)
            .unwrap_or(path_bytes.len());

        let path_str = core::str::from_utf8(&path_bytes[..null_pos])
            .map_err(|_| ElfError::InterpreterInvalidUtf8)?;

        if path_str.is_empty() {
            return Err(ElfError::InterpreterNotFound);
        }

        Ok(InterpreterInfo {
            path: path_str.into(),
        })
    }

    pub fn as_str(&self) -> &str {
        &self.path
    }

    pub fn is_nonos_ld(&self) -> bool {
        self.path == NONOS_INTERP || self.path.contains("ld-nonos")
    }

    pub fn is_glibc_ld(&self) -> bool {
        self.path.contains(known_interp::GLIBC_LD)
    }

    pub fn is_musl_ld(&self) -> bool {
        self.path.contains(known_interp::MUSL_LD)
    }

    pub fn is_known_ld(&self) -> bool {
        self.is_nonos_ld()
            || self.is_glibc_ld()
            || self.is_musl_ld()
            || self.path.contains(known_interp::GENERIC_LD)
    }

    pub fn is_foreign(&self) -> bool {
        !self.is_nonos_ld() && self.is_known_ld()
    }

    pub fn filename(&self) -> &str {
        self.path.rsplit('/').next().unwrap_or(&self.path)
    }

    pub fn is_absolute(&self) -> bool {
        self.path.starts_with('/')
    }

    pub fn directory(&self) -> &str {
        match self.path.rfind('/') {
            Some(pos) => &self.path[..pos],
            None => "",
        }
    }
}

impl Default for InterpreterInfo {
    fn default() -> Self {
        Self {
            path: String::new(),
        }
    }
}

impl From<String> for InterpreterInfo {
    fn from(path: String) -> Self {
        Self::new(path)
    }
}

impl From<&str> for InterpreterInfo {
    fn from(path: &str) -> Self {
        Self::new(path.into())
    }
}
