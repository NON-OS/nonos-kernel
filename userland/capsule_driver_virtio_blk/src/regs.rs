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

//! Volatile MMIO accessors for the BAR0 mapping the broker hands
//! us. Mirrors the register helper in capsule_driver_virtio_rng;
//! adds a 64-bit read for the device-config capacity field.

use core::ptr::{read_volatile, write_volatile};

#[derive(Debug, Clone, Copy)]
pub struct Regs {
    pub base: *mut u8,
}

impl Regs {
    pub const fn new(base: u64) -> Self {
        Self { base: base as *mut u8 }
    }

    /// # Safety
    /// `offset` must lie inside the BAR0 grant the broker handed
    /// the caller. The grant is bounds-checked when it is created;
    /// any offset less than the grant length is in-bounds.
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
    pub unsafe fn r64(self, offset: usize) -> u64 {
        let lo = read_volatile(self.base.add(offset).cast::<u32>()) as u64;
        let hi = read_volatile(self.base.add(offset + 4).cast::<u32>()) as u64;
        (hi << 32) | lo
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
}
