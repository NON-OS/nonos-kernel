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

use super::constants::reloc_type;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct RelaEntry {
    pub r_offset: u64,
    pub r_info: u64,
    pub r_addend: i64,
}

impl RelaEntry {
    pub const SIZE: usize = 24;

    #[inline]
    pub fn reloc_type(&self) -> u32 {
        (self.r_info & 0xFFFF_FFFF) as u32
    }

    #[inline]
    pub fn symbol_index(&self) -> u32 {
        (self.r_info >> 32) as u32
    }

    #[inline]
    pub fn make_info(sym: u32, typ: u32) -> u64 {
        ((sym as u64) << 32) | (typ as u64)
    }

    pub fn type_name(&self) -> &'static str {
        match self.reloc_type() {
            reloc_type::R_X86_64_NONE => "R_X86_64_NONE",
            reloc_type::R_X86_64_64 => "R_X86_64_64",
            reloc_type::R_X86_64_PC32 => "R_X86_64_PC32",
            reloc_type::R_X86_64_GOT32 => "R_X86_64_GOT32",
            reloc_type::R_X86_64_PLT32 => "R_X86_64_PLT32",
            reloc_type::R_X86_64_COPY => "R_X86_64_COPY",
            reloc_type::R_X86_64_GLOB_DAT => "R_X86_64_GLOB_DAT",
            reloc_type::R_X86_64_JUMP_SLOT => "R_X86_64_JUMP_SLOT",
            reloc_type::R_X86_64_RELATIVE => "R_X86_64_RELATIVE",
            reloc_type::R_X86_64_GOTPCREL => "R_X86_64_GOTPCREL",
            reloc_type::R_X86_64_32 => "R_X86_64_32",
            reloc_type::R_X86_64_32S => "R_X86_64_32S",
            _ => "UNKNOWN",
        }
    }
}

impl Default for RelaEntry {
    fn default() -> Self {
        Self {
            r_offset: 0,
            r_info: 0,
            r_addend: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_rela_entry_size() {
        assert_eq!(mem::size_of::<RelaEntry>(), RelaEntry::SIZE);
    }

    #[test]
    fn test_rela_entry_info() {
        let mut rela = RelaEntry::default();
        rela.r_info = RelaEntry::make_info(42, reloc_type::R_X86_64_64);

        assert_eq!(rela.symbol_index(), 42);
        assert_eq!(rela.reloc_type(), reloc_type::R_X86_64_64);
        assert_eq!(rela.type_name(), "R_X86_64_64");
    }
}
