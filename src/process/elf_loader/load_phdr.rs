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

use super::types::*;
use alloc::string::String;

pub fn load_interp(data: &[u8], phdr: &Elf64ProgramHeader) -> Result<String, ElfError> {
    let interp_offset = phdr.p_offset as usize;
    let interp_size = phdr.p_filesz as usize;
    if interp_offset + interp_size > data.len() {
        return Err(ElfError::InvalidProgramHeader);
    }
    let interp_bytes = &data[interp_offset..interp_offset + interp_size];
    let interp_len = interp_bytes.iter().position(|&c| c == 0).unwrap_or(interp_size);
    let interp_str = core::str::from_utf8(&interp_bytes[..interp_len])
        .map_err(|_| ElfError::InvalidProgramHeader)?;
    Ok(String::from(interp_str))
}

pub fn handle_gnu_stack(phdr: &Elf64ProgramHeader) -> bool {
    let exec_stack = phdr.p_flags & PF_X != 0;
    if exec_stack && crate::security::policy::advanced::enforce_nx_stack() {
        crate::security::monitoring::audit::log_security_event(
            "elf",
            crate::security::monitoring::audit::AuditSeverity::Warning,
            alloc::format!("Executable stack denied"),
            None,
            None,
            None,
        );
        return false;
    }
    exec_stack
}

pub fn find_phdr_addr(header: &Elf64Header, segments: &[LoadedSegment]) -> u64 {
    if header.e_phoff == 0 {
        return 0;
    }
    let phdr_size = header.e_phnum as u64 * header.e_phentsize as u64;
    for seg in segments {
        if seg.file_offset <= header.e_phoff
            && seg.file_offset + seg.filesz >= header.e_phoff + phdr_size
        {
            return seg.vaddr + (header.e_phoff - seg.file_offset);
        }
    }
    0
}
