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

use core::fmt;

use super::super::constants::DMA_ALIGNMENT;

#[repr(C, packed)]
#[derive(Clone, Copy)]
pub struct BdlEntry {
    pub addr_lo: u32,
    pub addr_hi: u32,
    pub length: u32,
    pub flags: u32,
}

impl BdlEntry {
    pub const IOC_FLAG: u32 = 1 << 0;

    #[inline]
    pub const fn new(phys_addr: u64, length: u32, ioc: bool) -> Self {
        debug_assert!(phys_addr % DMA_ALIGNMENT as u64 == 0, "BDL address must be 128-byte aligned");

        Self {
            addr_lo: (phys_addr & 0xFFFF_FFFF) as u32,
            addr_hi: (phys_addr >> 32) as u32,
            length,
            flags: if ioc { Self::IOC_FLAG } else { 0 },
        }
    }

    #[inline]
    pub const fn zeroed() -> Self {
        Self {
            addr_lo: 0,
            addr_hi: 0,
            length: 0,
            flags: 0,
        }
    }

    #[inline]
    pub const fn phys_addr(&self) -> u64 {
        ((self.addr_hi as u64) << 32) | (self.addr_lo as u64)
    }

    #[inline]
    pub const fn has_ioc(&self) -> bool {
        (self.flags & Self::IOC_FLAG) != 0
    }

    #[inline]
    pub const fn len(&self) -> u32 {
        self.length
    }

    #[inline]
    pub const fn is_empty(&self) -> bool {
        self.length == 0
    }

    #[inline]
    pub const fn is_valid(&self) -> bool {
        self.length > 0 && (self.phys_addr() % DMA_ALIGNMENT as u64 == 0)
    }
}

impl fmt::Debug for BdlEntry {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let addr_lo = { self.addr_lo };
        let addr_hi = { self.addr_hi };
        let length = { self.length };
        let flags = { self.flags };

        f.debug_struct("BdlEntry")
            .field("phys_addr", &format_args!("{:#018X}", ((addr_hi as u64) << 32) | addr_lo as u64))
            .field("length", &length)
            .field("ioc", &(flags & Self::IOC_FLAG != 0))
            .finish()
    }
}

const _: () = assert!(core::mem::size_of::<BdlEntry>() == 16);
