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
use crate::arch::fdt::property::Property;
use crate::arch::fdt::strings::resolve;
use crate::arch::fdt::tokens::{FDT_BEGIN_NODE, FDT_END, FDT_END_NODE, FDT_NOP, FDT_PROP};

use super::align::align4;
use super::event::Event;

pub struct Walker<'a> {
    structure: &'a [u8],
    strings: &'a [u8],
    cursor: usize,
}

impl<'a> Walker<'a> {
    pub fn new(structure: &'a [u8], strings: &'a [u8]) -> Self {
        Self { structure, strings, cursor: 0 }
    }

    pub fn next(&mut self) -> Result<Option<Event<'a>>, FdtError> {
        loop {
            if self.cursor >= self.structure.len() {
                return Ok(None);
            }
            if self.cursor % 4 != 0 {
                return Err(FdtError::UnalignedToken);
            }
            let tok = be_u32(self.structure, self.cursor)?;
            self.cursor += 4;
            match tok {
                FDT_BEGIN_NODE => return self.read_begin_node().map(Some),
                FDT_END_NODE => return Ok(Some(Event::EndNode)),
                FDT_PROP => return self.read_property().map(Some),
                FDT_NOP => continue,
                FDT_END => return Ok(None),
                _ => return Err(FdtError::UnknownToken),
            }
        }
    }

    fn read_begin_node(&mut self) -> Result<Event<'a>, FdtError> {
        let start = self.cursor;
        let mut end = start;
        while end < self.structure.len() && self.structure[end] != 0 {
            end += 1;
        }
        if end == self.structure.len() {
            return Err(FdtError::TruncatedNodeName);
        }
        let name = &self.structure[start..end];
        self.cursor = align4(end + 1);
        Ok(Event::BeginNode { name })
    }

    fn read_property(&mut self) -> Result<Event<'a>, FdtError> {
        if self.cursor + 8 > self.structure.len() {
            return Err(FdtError::TruncatedProperty);
        }
        let len = be_u32(self.structure, self.cursor)? as usize;
        let nameoff = be_u32(self.structure, self.cursor + 4)?;
        self.cursor += 8;
        if self.cursor + len > self.structure.len() {
            return Err(FdtError::TruncatedProperty);
        }
        let data = &self.structure[self.cursor..self.cursor + len];
        self.cursor = align4(self.cursor + len);
        let name = resolve(self.strings, nameoff)?;
        Ok(Event::Property(Property { name, data }))
    }
}
