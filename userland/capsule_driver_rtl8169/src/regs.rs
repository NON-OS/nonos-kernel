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

use core::ptr;

#[derive(Clone, Copy)]
pub struct Regs {
    base: u64,
}

impl Regs {
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    pub unsafe fn r8(&self, offset: usize) -> u8 {
        ptr::read_volatile((self.base as usize + offset) as *const u8)
    }

    pub unsafe fn r16(&self, offset: usize) -> u16 {
        ptr::read_volatile((self.base as usize + offset) as *const u16)
    }

    pub unsafe fn w8(&self, offset: usize, value: u8) {
        ptr::write_volatile((self.base as usize + offset) as *mut u8, value);
    }

    pub unsafe fn w16(&self, offset: usize, value: u16) {
        ptr::write_volatile((self.base as usize + offset) as *mut u16, value);
    }

    pub unsafe fn w32(&self, offset: usize, value: u32) {
        ptr::write_volatile((self.base as usize + offset) as *mut u32, value);
    }
}
