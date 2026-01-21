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

use crate::arch::x86_64::gdt::constants::*;
use crate::arch::x86_64::gdt::error::GdtError;

#[repr(C, packed)]
#[derive(Clone, Copy, Debug)]
pub struct TssEntry {
    pub limit_low: u16,
    pub base_low: u16,
    pub base_mid: u8,
    pub access: u8,
    pub limit_flags: u8,
    pub base_high: u8,
    pub base_upper: u32,
    pub reserved: u32,
}

impl TssEntry {
    pub const fn empty() -> Self {
        Self {
            limit_low: 0,
            base_low: 0,
            base_mid: 0,
            access: 0,
            limit_flags: 0,
            base_high: 0,
            base_upper: 0,
            reserved: 0,
        }
    }

    pub fn new(base: u64, limit: u32) -> Self {
        Self {
            limit_low: (limit & 0xFFFF) as u16,
            base_low: (base & 0xFFFF) as u16,
            base_mid: ((base >> 16) & 0xFF) as u8,
            access: ACCESS_PRESENT | ACCESS_TYPE_SYSTEM | TSS_TYPE_AVAILABLE_64,
            limit_flags: ((limit >> 16) & 0x0F) as u8,
            base_high: ((base >> 24) & 0xFF) as u8,
            base_upper: (base >> 32) as u32,
            reserved: 0,
        }
    }

    pub fn set_base(&mut self, base: u64) {
        self.base_low = (base & 0xFFFF) as u16;
        self.base_mid = ((base >> 16) & 0xFF) as u8;
        self.base_high = ((base >> 24) & 0xFF) as u8;
        self.base_upper = (base >> 32) as u32;
    }

    pub fn base(&self) -> u64 {
        (self.base_low as u64)
            | ((self.base_mid as u64) << 16)
            | ((self.base_high as u64) << 24)
            | ((self.base_upper as u64) << 32)
    }

    pub fn is_busy(&self) -> bool {
        (self.access & 0x0F) == TSS_TYPE_BUSY_64
    }
}

#[repr(C, packed)]
pub struct Tss {
    reserved1: u32,
    pub rsp: [u64; 3],
    reserved2: u64,
    pub ist: [u64; 7],
    reserved3: u64,
    reserved4: u16,
    pub iomap_base: u16,
}

impl Tss {
    pub const fn new() -> Self {
        Self {
            reserved1: 0,
            rsp: [0; 3],
            reserved2: 0,
            ist: [0; 7],
            reserved3: 0,
            reserved4: 0,
            iomap_base: TSS_SIZE as u16,
        }
    }

    #[inline]
    pub fn set_rsp0(&mut self, rsp: u64) {
        self.rsp[0] = rsp;
    }

    #[inline]
    pub fn rsp0(&self) -> u64 {
        self.rsp[0]
    }

    pub fn set_rsp(&mut self, ring: usize, rsp: u64) -> Result<(), GdtError> {
        if ring > 2 {
            return Err(GdtError::InvalidRspIndex);
        }
        self.rsp[ring] = rsp;
        Ok(())
    }

    pub fn get_rsp(&self, ring: usize) -> Result<u64, GdtError> {
        if ring > 2 {
            return Err(GdtError::InvalidRspIndex);
        }
        Ok(self.rsp[ring])
    }

    pub fn set_ist(&mut self, index: usize, stack_top: u64) -> Result<(), GdtError> {
        if index < 1 || index > 7 {
            return Err(GdtError::InvalidIstIndex);
        }
        self.ist[index - 1] = stack_top;
        Ok(())
    }

    pub fn get_ist(&self, index: usize) -> Result<u64, GdtError> {
        if index < 1 || index > 7 {
            return Err(GdtError::InvalidIstIndex);
        }
        Ok(self.ist[index - 1])
    }

    pub fn set_iomap_base(&mut self, offset: u16) {
        self.iomap_base = offset;
    }

    pub fn disable_iomap(&mut self) {
        self.iomap_base = TSS_SIZE as u16;
    }
}
