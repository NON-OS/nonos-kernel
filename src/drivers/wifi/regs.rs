// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use x86_64::VirtAddr;

pub struct WifiRegs {
    base: VirtAddr,
}

impl WifiRegs {
    pub fn new(base: VirtAddr) -> Self {
        Self { base }
    }

    #[inline]
    pub fn read32(&self, offset: u32) -> u32 {
        // SAFETY: base + offset is a valid MMIO address mapped during device init.
        unsafe {
            let addr = (self.base.as_u64() + offset as u64) as *const u32;
            core::ptr::read_volatile(addr)
        }
    }

    #[inline]
    pub fn write32(&self, offset: u32, value: u32) {
        // SAFETY: base + offset is a valid MMIO address mapped during device init.
        unsafe {
            let addr = (self.base.as_u64() + offset as u64) as *mut u32;
            core::ptr::write_volatile(addr, value);
        }
    }

    #[inline]
    pub fn set_bits(&self, offset: u32, bits: u32) {
        let val = self.read32(offset);
        self.write32(offset, val | bits);
    }

    #[inline]
    pub fn clear_bits(&self, offset: u32, bits: u32) {
        let val = self.read32(offset);
        self.write32(offset, val & !bits);
    }

    #[inline]
    pub fn poll(&self, offset: u32, mask: u32, expected: u32, timeout_us: u64) -> bool {
        let start = Self::timestamp();
        loop {
            if (self.read32(offset) & mask) == expected {
                return true;
            }
            if Self::timestamp() - start > timeout_us {
                return false;
            }
            core::hint::spin_loop();
        }
    }

    fn timestamp() -> u64 {
        crate::arch::x86_64::time::tsc::elapsed_us()
    }

    pub fn read_prph(&self, addr: u32) -> u32 {
        use super::constants::*;
        self.write32(csr::EEPROM_REG, INT_MASK_DISABLED);
        self.write32(PRPH_DWORD, addr | PRPH_READ_FLAG);
        core::hint::spin_loop();
        self.read32(PRPH_DATA)
    }

    pub fn write_prph(&self, addr: u32, val: u32) {
        use super::constants::*;
        self.write32(PRPH_DWORD, addr | PRPH_READ_FLAG);
        core::hint::spin_loop();
        self.write32(PRPH_DATA, val);
    }

    pub fn read_mem(&self, addr: u32) -> u32 {
        use super::constants::*;
        self.write32(HBUS_TARG_MEM_RADDR, addr);
        core::hint::spin_loop();
        self.read32(HBUS_TARG_MEM_WDAT)
    }

    pub fn write_mem(&self, addr: u32, val: u32) {
        use super::constants::*;
        self.write32(HBUS_TARG_MEM_RADDR, addr);
        core::hint::spin_loop();
        self.write32(HBUS_TARG_MEM_WDAT, val);
    }
}
