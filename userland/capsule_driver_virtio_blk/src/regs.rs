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

//! Register access for the virtio-pci legacy register window. QEMU
//! transitional devices expose this as BAR0 PIO; older internal
//! fixtures may expose the same layout as MMIO. Both paths remain
//! behind broker grants.

use core::ptr::{read_volatile, write_volatile};
use nonos_libc::{mk_pio_read, mk_pio_write};

#[derive(Debug, Clone, Copy)]
pub struct Regs {
    io: RegIo,
}

#[derive(Debug, Clone, Copy)]
enum RegIo {
    Mmio(*mut u8),
    Pio(u64),
}

impl Regs {
    pub const fn mmio(base: u64) -> Self {
        Self { io: RegIo::Mmio(base as *mut u8) }
    }

    pub const fn pio(grant_id: u64) -> Self {
        Self { io: RegIo::Pio(grant_id) }
    }

    /// # Safety
    /// `offset` must lie inside the BAR0 grant the broker handed
    /// the caller. The grant is bounds-checked when it is created;
    /// any offset less than the grant length is in-bounds.
    #[inline]
    pub unsafe fn r8(self, offset: usize) -> u8 {
        match self.io {
            RegIo::Mmio(base) => read_volatile(base.add(offset)),
            RegIo::Pio(grant) => read_pio(grant, offset, 1) as u8,
        }
    }

    #[inline]
    pub unsafe fn r16(self, offset: usize) -> u16 {
        match self.io {
            RegIo::Mmio(base) => read_volatile(base.add(offset).cast()),
            RegIo::Pio(grant) => read_pio(grant, offset, 2) as u16,
        }
    }

    #[inline]
    pub unsafe fn r32(self, offset: usize) -> u32 {
        match self.io {
            RegIo::Mmio(base) => read_volatile(base.add(offset).cast()),
            RegIo::Pio(grant) => read_pio(grant, offset, 4),
        }
    }

    #[inline]
    pub unsafe fn r64(self, offset: usize) -> u64 {
        let lo = self.r32(offset) as u64;
        let hi = self.r32(offset + 4) as u64;
        (hi << 32) | lo
    }

    #[inline]
    pub unsafe fn w8(self, offset: usize, value: u8) {
        match self.io {
            RegIo::Mmio(base) => write_volatile(base.add(offset), value),
            RegIo::Pio(grant) => write_pio(grant, offset, 1, value as u32),
        }
    }

    #[inline]
    pub unsafe fn w16(self, offset: usize, value: u16) {
        match self.io {
            RegIo::Mmio(base) => write_volatile(base.add(offset).cast(), value),
            RegIo::Pio(grant) => write_pio(grant, offset, 2, value as u32),
        }
    }

    #[inline]
    pub unsafe fn w32(self, offset: usize, value: u32) {
        match self.io {
            RegIo::Mmio(base) => write_volatile(base.add(offset).cast(), value),
            RegIo::Pio(grant) => write_pio(grant, offset, 4, value),
        }
    }
}

fn read_pio(grant: u64, offset: usize, width: u8) -> u32 {
    let mut value = 0u32;
    let _ = mk_pio_read(grant, offset as u16, width, &mut value);
    value
}

fn write_pio(grant: u64, offset: usize, width: u8, value: u32) {
    let _ = mk_pio_write(grant, offset as u16, width, value);
}
