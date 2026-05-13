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

use crate::arch::fdt::endian::be_u32;
use crate::arch::fdt::error::FdtError;

use super::reg_iter::RegIter;
use super::string_list::StringList;

#[derive(Debug, Clone, Copy)]
pub struct Property<'a> {
    pub name: &'a [u8],
    pub data: &'a [u8],
}

impl<'a> Property<'a> {
    pub fn u32(&self) -> Result<u32, FdtError> {
        be_u32(self.data, 0)
    }

    pub fn reg_iter(&self, address_cells: u32, size_cells: u32) -> RegIter<'a> {
        RegIter::new(self.data, address_cells, size_cells)
    }

    pub fn stringlist(&self) -> StringList<'a> {
        StringList::new(self.data)
    }

    pub fn compatible_matches(&self, needle: &[u8]) -> bool {
        for s in self.stringlist() {
            if s == needle {
                return true;
            }
        }
        false
    }
}
