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

use super::constants::dyn_tag;

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct DynamicEntry {
    pub d_tag: u64,
    pub value: u64,
}

impl DynamicEntry {
    pub const SIZE: usize = 16;

    #[inline]
    pub fn is_null(&self) -> bool {
        self.d_tag == dyn_tag::DT_NULL
    }

    pub fn tag_name(&self) -> &'static str {
        match self.d_tag {
            dyn_tag::DT_NULL => "NULL",
            dyn_tag::DT_NEEDED => "NEEDED",
            dyn_tag::DT_PLTRELSZ => "PLTRELSZ",
            dyn_tag::DT_PLTGOT => "PLTGOT",
            dyn_tag::DT_HASH => "HASH",
            dyn_tag::DT_STRTAB => "STRTAB",
            dyn_tag::DT_SYMTAB => "SYMTAB",
            dyn_tag::DT_RELA => "RELA",
            dyn_tag::DT_RELASZ => "RELASZ",
            dyn_tag::DT_RELAENT => "RELAENT",
            dyn_tag::DT_STRSZ => "STRSZ",
            dyn_tag::DT_SYMENT => "SYMENT",
            dyn_tag::DT_INIT => "INIT",
            dyn_tag::DT_FINI => "FINI",
            dyn_tag::DT_SONAME => "SONAME",
            dyn_tag::DT_RPATH => "RPATH",
            dyn_tag::DT_JMPREL => "JMPREL",
            dyn_tag::DT_INIT_ARRAY => "INIT_ARRAY",
            dyn_tag::DT_FINI_ARRAY => "FINI_ARRAY",
            _ => "UNKNOWN",
        }
    }
}

impl Default for DynamicEntry {
    fn default() -> Self {
        Self { d_tag: 0, value: 0 }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_dynamic_entry_size() {
        assert_eq!(mem::size_of::<DynamicEntry>(), DynamicEntry::SIZE);
    }

    #[test]
    fn test_dynamic_entry() {
        let mut dyn_entry = DynamicEntry::default();
        assert!(dyn_entry.is_null());

        dyn_entry.d_tag = dyn_tag::DT_NEEDED;
        assert!(!dyn_entry.is_null());
        assert_eq!(dyn_entry.tag_name(), "NEEDED");
    }
}
