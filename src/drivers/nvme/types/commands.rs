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

use core::mem;

#[repr(C, align(64))]
#[derive(Clone, Copy)]
pub struct SubmissionEntry {
    pub cdw0: u32,
    pub nsid: u32,
    pub cdw2: u32,
    pub cdw3: u32,
    pub mptr: u64,
    pub prp1: u64,
    pub prp2: u64,
    pub cdw10: u32,
    pub cdw11: u32,
    pub cdw12: u32,
    pub cdw13: u32,
    pub cdw14: u32,
    pub cdw15: u32,
}

impl SubmissionEntry {
    pub const SIZE: usize = mem::size_of::<Self>();

    #[inline]
    pub const fn new() -> Self {
        Self {
            cdw0: 0,
            nsid: 0,
            cdw2: 0,
            cdw3: 0,
            mptr: 0,
            prp1: 0,
            prp2: 0,
            cdw10: 0,
            cdw11: 0,
            cdw12: 0,
            cdw13: 0,
            cdw14: 0,
            cdw15: 0,
        }
    }

    #[inline]
    pub fn set_opcode(&mut self, opcode: u8) {
        self.cdw0 = (self.cdw0 & !0xFF) | (opcode as u32);
    }

    #[inline]
    pub fn set_fuse(&mut self, fuse: u8) {
        self.cdw0 = (self.cdw0 & !(0x3 << 8)) | (((fuse & 0x3) as u32) << 8);
    }

    #[inline]
    pub fn set_psdt(&mut self, psdt: u8) {
        self.cdw0 = (self.cdw0 & !(0x3 << 14)) | (((psdt & 0x3) as u32) << 14);
    }

    #[inline]
    pub fn set_cid(&mut self, cid: u16) {
        self.cdw0 = (self.cdw0 & 0xFFFF) | ((cid as u32) << 16);
    }

    #[inline]
    pub const fn opcode(&self) -> u8 {
        (self.cdw0 & 0xFF) as u8
    }

    #[inline]
    pub const fn cid(&self) -> u16 {
        ((self.cdw0 >> 16) & 0xFFFF) as u16
    }

    pub fn sanitize(&mut self) {
        self.cdw2 = 0;
        self.cdw3 = 0;
        self.cdw0 &= 0xFFFF_C3FF;
    }
}

impl Default for SubmissionEntry {
    fn default() -> Self {
        Self::new()
    }
}
