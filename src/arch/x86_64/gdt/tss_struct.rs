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

use crate::arch::x86_64::gdt::constants::*;
use crate::arch::x86_64::gdt::error::GdtError;

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
        Self { reserved1: 0, rsp: [0; 3], reserved2: 0, ist: [0; 7], reserved3: 0, reserved4: 0, iomap_base: TSS_SIZE as u16 }
    }

    #[inline] pub fn set_rsp0(&mut self, rsp: u64) { self.rsp[0] = rsp; }
    #[inline] pub fn rsp0(&self) -> u64 { self.rsp[0] }

    pub fn set_rsp(&mut self, ring: usize, rsp: u64) -> Result<(), GdtError> {
        if ring > 2 { return Err(GdtError::InvalidRspIndex); }
        self.rsp[ring] = rsp;
        Ok(())
    }

    pub fn get_rsp(&self, ring: usize) -> Result<u64, GdtError> {
        if ring > 2 { return Err(GdtError::InvalidRspIndex); }
        Ok(self.rsp[ring])
    }

    pub fn set_ist(&mut self, index: usize, stack_top: u64) -> Result<(), GdtError> {
        if index < 1 || index > 7 { return Err(GdtError::InvalidIstIndex); }
        self.ist[index - 1] = stack_top;
        Ok(())
    }

    pub fn get_ist(&self, index: usize) -> Result<u64, GdtError> {
        if index < 1 || index > 7 { return Err(GdtError::InvalidIstIndex); }
        Ok(self.ist[index - 1])
    }

    pub fn set_iomap_base(&mut self, offset: u16) { self.iomap_base = offset; }
    pub fn disable_iomap(&mut self) { self.iomap_base = TSS_SIZE as u16; }
}
