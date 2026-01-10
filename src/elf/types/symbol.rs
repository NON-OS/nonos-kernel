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

use super::constants::{sym_bind, sym_type};

#[repr(C)]
#[derive(Debug, Clone, Copy)]
pub struct Symbol {
    pub st_name: u32,
    pub st_info: u8,
    pub st_other: u8,
    pub st_shndx: u16,
    pub st_value: u64,
    pub st_size: u64,
}

impl Symbol {
    pub const SIZE: usize = 24;

    #[inline]
    pub fn binding(&self) -> u8 {
        self.st_info >> 4
    }

    #[inline]
    pub fn sym_type(&self) -> u8 {
        self.st_info & 0x0F
    }

    #[inline]
    pub fn is_local(&self) -> bool {
        self.binding() == sym_bind::STB_LOCAL
    }

    #[inline]
    pub fn is_global(&self) -> bool {
        self.binding() == sym_bind::STB_GLOBAL
    }

    #[inline]
    pub fn is_weak(&self) -> bool {
        self.binding() == sym_bind::STB_WEAK
    }

    #[inline]
    pub fn is_function(&self) -> bool {
        self.sym_type() == sym_type::STT_FUNC
    }

    #[inline]
    pub fn is_object(&self) -> bool {
        self.sym_type() == sym_type::STT_OBJECT
    }

    #[inline]
    pub fn is_undefined(&self) -> bool {
        self.st_shndx == 0
    }
}

impl Default for Symbol {
    fn default() -> Self {
        Self {
            st_name: 0,
            st_info: 0,
            st_other: 0,
            st_shndx: 0,
            st_value: 0,
            st_size: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem;

    #[test]
    fn test_symbol_size() {
        assert_eq!(mem::size_of::<Symbol>(), Symbol::SIZE);
    }

    #[test]
    fn test_symbol_info() {
        let mut sym = Symbol::default();
        sym.st_info = (sym_bind::STB_GLOBAL << 4) | sym_type::STT_FUNC;

        assert!(sym.is_global());
        assert!(!sym.is_local());
        assert!(sym.is_function());
        assert!(!sym.is_object());
    }
}
