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

use super::core::VirtioRngDevice;
use super::types::AccessMode;
use core::ptr;

impl VirtioRngDevice {
    #[inline]
    pub(super) fn read8(&self, offset: u16) -> u8 {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                let val: u8;
                unsafe {
                    core::arch::asm!("in al, dx", out("al") val, in("dx") port, options(nostack, preserves_flags));
                }
                val
            }
            AccessMode::Mmio(base) => unsafe {
                ptr::read_volatile((*base + offset as u64) as *const u8)
            },
        }
    }
    #[inline]
    pub(super) fn write8(&self, offset: u16, val: u8) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                unsafe {
                    core::arch::asm!("out dx, al", in("dx") port, in("al") val, options(nostack, preserves_flags));
                }
            }
            AccessMode::Mmio(base) => unsafe {
                ptr::write_volatile((*base + offset as u64) as *mut u8, val);
            },
        }
    }
    #[inline]
    pub(super) fn read16(&self, offset: u16) -> u16 {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                let val: u16;
                unsafe {
                    core::arch::asm!("in ax, dx", out("ax") val, in("dx") port, options(nostack, preserves_flags));
                }
                val
            }
            AccessMode::Mmio(base) => unsafe {
                ptr::read_volatile((*base + offset as u64) as *const u16)
            },
        }
    }
    #[inline]
    pub(super) fn write16(&self, offset: u16, val: u16) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                unsafe {
                    core::arch::asm!("out dx, ax", in("dx") port, in("ax") val, options(nostack, preserves_flags));
                }
            }
            AccessMode::Mmio(base) => unsafe {
                ptr::write_volatile((*base + offset as u64) as *mut u16, val);
            },
        }
    }
    #[inline]
    pub(super) fn read32(&self, offset: u16) -> u32 {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                let val: u32;
                unsafe {
                    core::arch::asm!("in eax, dx", out("eax") val, in("dx") port, options(nostack, preserves_flags));
                }
                val
            }
            AccessMode::Mmio(base) => unsafe {
                ptr::read_volatile((*base + offset as u64) as *const u32)
            },
        }
    }
    #[inline]
    pub(super) fn write32(&self, offset: u16, val: u32) {
        match &self.access {
            AccessMode::Io(iobase) => {
                let port = *iobase + offset;
                unsafe {
                    core::arch::asm!("out dx, eax", in("dx") port, in("eax") val, options(nostack, preserves_flags));
                }
            }
            AccessMode::Mmio(base) => unsafe {
                ptr::write_volatile((*base + offset as u64) as *mut u32, val);
            },
        }
    }
}
