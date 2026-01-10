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

use super::constants::{phdr_flags, phdr_type};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct ProgramHeader {
    pub p_type: u32,
    pub p_flags: u32,
    pub p_offset: u64,
    pub p_vaddr: u64,
    pub p_paddr: u64,
    pub p_filesz: u64,
    pub p_memsz: u64,
    pub p_align: u64,
}

impl ProgramHeader {
    pub const SIZE: usize = 56;

    #[inline]
    pub fn is_load(&self) -> bool {
        self.p_type == phdr_type::PT_LOAD
    }

    #[inline]
    pub fn is_readable(&self) -> bool {
        self.p_flags & phdr_flags::PF_R != 0
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        self.p_flags & phdr_flags::PF_W != 0
    }

    #[inline]
    pub fn is_executable(&self) -> bool {
        self.p_flags & phdr_flags::PF_X != 0
    }

    #[inline]
    pub fn bss_size(&self) -> u64 {
        self.p_memsz.saturating_sub(self.p_filesz)
    }

    pub fn type_name(&self) -> &'static str {
        match self.p_type {
            phdr_type::PT_NULL => "NULL",
            phdr_type::PT_LOAD => "LOAD",
            phdr_type::PT_DYNAMIC => "DYNAMIC",
            phdr_type::PT_INTERP => "INTERP",
            phdr_type::PT_NOTE => "NOTE",
            phdr_type::PT_PHDR => "PHDR",
            phdr_type::PT_TLS => "TLS",
            phdr_type::PT_GNU_STACK => "GNU_STACK",
            phdr_type::PT_GNU_RELRO => "GNU_RELRO",
            _ => "UNKNOWN",
        }
    }

    pub fn flags_str(&self) -> &'static str {
        match (self.is_readable(), self.is_writable(), self.is_executable()) {
            (true, true, true) => "RWX",
            (true, true, false) => "RW-",
            (true, false, true) => "R-X",
            (true, false, false) => "R--",
            (false, true, true) => "-WX",
            (false, true, false) => "-W-",
            (false, false, true) => "--X",
            (false, false, false) => "---",
        }
    }
}

impl Default for ProgramHeader {
    fn default() -> Self {
        Self {
            p_type: 0,
            p_flags: 0,
            p_offset: 0,
            p_vaddr: 0,
            p_paddr: 0,
            p_filesz: 0,
            p_memsz: 0,
            p_align: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_program_header_size() {
        assert_eq!(mem::size_of::<ProgramHeader>(), ProgramHeader::SIZE);
    }

    #[test]
    fn test_program_header_flags() {
        let mut ph = ProgramHeader::default();
        ph.p_type = phdr_type::PT_LOAD;
        ph.p_flags = phdr_flags::PF_R | phdr_flags::PF_X;

        assert!(ph.is_load());
        assert!(ph.is_readable());
        assert!(!ph.is_writable());
        assert!(ph.is_executable());
        assert_eq!(ph.flags_str(), "R-X");
    }

    #[test]
    fn test_program_header_bss() {
        let mut ph = ProgramHeader::default();
        ph.p_filesz = 0x1000;
        ph.p_memsz = 0x2000;

        assert_eq!(ph.bss_size(), 0x1000);
    }
}
