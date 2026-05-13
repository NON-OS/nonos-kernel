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

use crate::arch::fdt::endian::be_cells;

pub struct RegIter<'a> {
    data: &'a [u8],
    offset: usize,
    address_cells: u32,
    size_cells: u32,
}

impl<'a> RegIter<'a> {
    pub fn new(data: &'a [u8], address_cells: u32, size_cells: u32) -> Self {
        Self { data, offset: 0, address_cells, size_cells }
    }
}

impl<'a> Iterator for RegIter<'a> {
    type Item = (u64, u64);

    fn next(&mut self) -> Option<Self::Item> {
        let cell_bytes = ((self.address_cells + self.size_cells) * 4) as usize;
        if self.offset + cell_bytes > self.data.len() {
            return None;
        }
        let addr = be_cells(self.data, self.offset, self.address_cells).ok()?;
        let size_off = self.offset + (self.address_cells * 4) as usize;
        let size = be_cells(self.data, size_off, self.size_cells).ok()?;
        self.offset += cell_bytes;
        Some((addr, size))
    }
}
