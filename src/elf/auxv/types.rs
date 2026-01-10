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

pub mod aux_type {
    pub const AT_NULL: u64 = 0;
    pub const AT_IGNORE: u64 = 1;
    pub const AT_EXECFD: u64 = 2;
    pub const AT_PHDR: u64 = 3;
    pub const AT_PHENT: u64 = 4;
    pub const AT_PHNUM: u64 = 5;
    pub const AT_PAGESZ: u64 = 6;
    pub const AT_BASE: u64 = 7;
    pub const AT_FLAGS: u64 = 8;
    pub const AT_ENTRY: u64 = 9;
    pub const AT_NOTELF: u64 = 10;
    pub const AT_UID: u64 = 11;
    pub const AT_EUID: u64 = 12;
    pub const AT_GID: u64 = 13;
    pub const AT_EGID: u64 = 14;
    pub const AT_PLATFORM: u64 = 15;
    pub const AT_HWCAP: u64 = 16;
    pub const AT_CLKTCK: u64 = 17;
    pub const AT_SECURE: u64 = 23;
    pub const AT_BASE_PLATFORM: u64 = 24;
    pub const AT_RANDOM: u64 = 25;
    pub const AT_HWCAP2: u64 = 26;
    pub const AT_EXECFN: u64 = 31;
    pub const AT_SYSINFO_EHDR: u64 = 33;
}

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct AuxEntry {
    pub a_type: u64,
    pub a_val: u64,
}

impl AuxEntry {
    pub const SIZE: usize = 16;

    pub const fn new(a_type: u64, a_val: u64) -> Self {
        Self { a_type, a_val }
    }

    pub const fn null() -> Self {
        Self { a_type: aux_type::AT_NULL, a_val: 0 }
    }

    pub fn is_null(&self) -> bool {
        self.a_type == aux_type::AT_NULL
    }

    pub fn type_name(&self) -> &'static str {
        match self.a_type {
            aux_type::AT_NULL => "AT_NULL",
            aux_type::AT_IGNORE => "AT_IGNORE",
            aux_type::AT_EXECFD => "AT_EXECFD",
            aux_type::AT_PHDR => "AT_PHDR",
            aux_type::AT_PHENT => "AT_PHENT",
            aux_type::AT_PHNUM => "AT_PHNUM",
            aux_type::AT_PAGESZ => "AT_PAGESZ",
            aux_type::AT_BASE => "AT_BASE",
            aux_type::AT_FLAGS => "AT_FLAGS",
            aux_type::AT_ENTRY => "AT_ENTRY",
            aux_type::AT_UID => "AT_UID",
            aux_type::AT_EUID => "AT_EUID",
            aux_type::AT_GID => "AT_GID",
            aux_type::AT_EGID => "AT_EGID",
            aux_type::AT_PLATFORM => "AT_PLATFORM",
            aux_type::AT_HWCAP => "AT_HWCAP",
            aux_type::AT_CLKTCK => "AT_CLKTCK",
            aux_type::AT_SECURE => "AT_SECURE",
            aux_type::AT_RANDOM => "AT_RANDOM",
            aux_type::AT_HWCAP2 => "AT_HWCAP2",
            aux_type::AT_EXECFN => "AT_EXECFN",
            aux_type::AT_SYSINFO_EHDR => "AT_SYSINFO_EHDR",
            _ => "AT_UNKNOWN",
        }
    }
}

impl Default for AuxEntry {
    fn default() -> Self {
        Self::null()
    }
}
