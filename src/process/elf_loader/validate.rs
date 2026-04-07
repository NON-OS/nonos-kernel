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

pub const USER_SPACE_END: u64 = 0x0000_8000_0000_0000;

pub fn validate_user_address(addr: u64, size: u64) -> Result<(), ElfError> {
    if addr >= USER_SPACE_END { return Err(ElfError::InvalidAddress); }
    if let Some(end) = addr.checked_add(size) {
        if end > USER_SPACE_END { return Err(ElfError::InvalidAddress); }
    } else {
        return Err(ElfError::InvalidAddress);
    }
    Ok(())
}

pub fn validate_wx_segment(phdr: &Elf64ProgramHeader) -> Result<(), ElfError> {
    if phdr.p_flags & PF_W != 0 && phdr.p_flags & PF_X != 0 {
        if crate::security::policy::advanced::enforce_wx_policy() {
            crate::security::monitoring::audit::log_security_event(
                "elf", crate::security::monitoring::audit::AuditSeverity::Critical,
                alloc::format!("W+X segment rejected at {:#x}", phdr.p_vaddr), None, None, None);
            return Err(ElfError::WXViolation);
        }
    }
    Ok(())
}

pub fn validate_alignment(phdr: &Elf64ProgramHeader) -> Result<(), ElfError> {
    if phdr.p_align > 1 && phdr.p_vaddr % phdr.p_align != phdr.p_offset % phdr.p_align {
        return Err(ElfError::InvalidAlignment);
    }
    Ok(())
}
