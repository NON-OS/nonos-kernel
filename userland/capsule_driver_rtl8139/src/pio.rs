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

use nonos_libc::{mk_pio_read, mk_pio_write};

#[derive(Clone, Copy)]
pub struct Pio {
    grant: u64,
}

impl Pio {
    pub const fn new(grant: u64) -> Self {
        Self { grant }
    }

    pub fn r8(&self, off: u16) -> Result<u8, &'static str> {
        self.read(off, 1).map(|v| v as u8)
    }

    pub fn r16(&self, off: u16) -> Result<u16, &'static str> {
        self.read(off, 2).map(|v| v as u16)
    }

    pub fn r32(&self, off: u16) -> Result<u32, &'static str> {
        self.read(off, 4)
    }

    pub fn w8(&self, off: u16, value: u8) -> Result<(), &'static str> {
        self.write(off, 1, value as u32)
    }

    pub fn w16(&self, off: u16, value: u16) -> Result<(), &'static str> {
        self.write(off, 2, value as u32)
    }

    pub fn w32(&self, off: u16, value: u32) -> Result<(), &'static str> {
        self.write(off, 4, value)
    }

    fn read(&self, off: u16, width: u8) -> Result<u32, &'static str> {
        let mut v = 0u32;
        if mk_pio_read(self.grant, off, width, &mut v) < 0 {
            Err("pio read failed")
        } else {
            Ok(v)
        }
    }

    fn write(&self, off: u16, width: u8, value: u32) -> Result<(), &'static str> {
        if mk_pio_write(self.grant, off, width, value) < 0 {
            Err("pio write failed")
        } else {
            Ok(())
        }
    }
}
