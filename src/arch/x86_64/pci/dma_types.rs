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

use x86_64::{PhysAddr, VirtAddr};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    ToDevice,
    FromDevice,
    Bidirectional,
}

pub struct DmaBuffer {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
    pub coherent: bool,
}

#[repr(C, align(16))]
#[derive(Debug, Clone, Copy)]
pub struct DmaDescriptor {
    pub addr: u64,
    pub length: u32,
    pub flags: u32,
}

impl DmaDescriptor {
    pub const FLAG_EOC: u32 = 0x8000_0000;
    pub const FLAG_IOC: u32 = 0x4000_0000;

    pub const fn new(addr: u64, length: u32, flags: u32) -> Self {
        Self { addr, length, flags }
    }

    pub fn set_end_of_chain(&mut self) {
        self.flags |= Self::FLAG_EOC;
    }

    pub fn set_interrupt(&mut self) {
        self.flags |= Self::FLAG_IOC;
    }
}
