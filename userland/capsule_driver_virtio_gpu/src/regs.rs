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

use core::ptr::{read_volatile, write_volatile};

#[derive(Clone, Copy)]
pub struct Regs {
    base: *mut u8,
    notify_offset: usize,
}

impl Regs {
    pub const fn new(base: u64) -> Self {
        Self { base: base as *mut u8, notify_offset: crate::constants::LEG_QUEUE_NOTIFY }
    }

    pub const fn with_notify(base: u64, notify_offset: usize) -> Self {
        Self { base: base as *mut u8, notify_offset }
    }

    #[inline]
    pub fn notify_ptr(self) -> *mut u16 {
        (self.base as usize + self.notify_offset) as *mut u16
    }

    #[inline]
    pub unsafe fn r8(self, offset: usize) -> u8 {
        read_volatile(self.base.add(offset))
    }

    #[inline]
    pub unsafe fn r16(self, offset: usize) -> u16 {
        read_volatile(self.base.add(offset).cast())
    }

    #[inline]
    pub unsafe fn r32(self, offset: usize) -> u32 {
        read_volatile(self.base.add(offset).cast())
    }

    #[inline]
    pub unsafe fn w8(self, offset: usize, value: u8) {
        write_volatile(self.base.add(offset), value)
    }

    #[inline]
    pub unsafe fn w16(self, offset: usize, value: u16) {
        write_volatile(self.base.add(offset).cast(), value)
    }

    #[inline]
    pub unsafe fn w32(self, offset: usize, value: u32) {
        write_volatile(self.base.add(offset).cast(), value)
    }

    #[inline]
    pub unsafe fn w64(self, offset: usize, value: u64) {
        write_volatile(self.base.add(offset).cast(), value)
    }
}
