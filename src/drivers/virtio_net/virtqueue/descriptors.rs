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

use super::super::constants::*;

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqDesc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

impl VirtqDesc {
    pub const SIZE: usize = 16;

    pub const fn new() -> Self {
        Self {
            addr: 0,
            len: 0,
            flags: 0,
            next: 0,
        }
    }

    pub fn has_next(&self) -> bool {
        (self.flags & VIRTQ_DESC_F_NEXT) != 0
    }

    pub fn is_write(&self) -> bool {
        (self.flags & VIRTQ_DESC_F_WRITE) != 0
    }

    pub fn is_indirect(&self) -> bool {
        (self.flags & VIRTQ_DESC_F_INDIRECT) != 0
    }

    pub fn clear(&mut self) {
        self.addr = 0;
        self.len = 0;
        self.flags = 0;
        self.next = 0;
    }
}

#[repr(C)]
pub struct VirtqAvail {
    pub flags: u16,
    pub idx: u16,
    pub ring: [u16; 0],
}

#[repr(C)]
#[derive(Clone, Copy, Debug, Default)]
pub struct VirtqUsedElem {
    pub id: u32,
    pub len: u32,
}

#[repr(C)]
pub struct VirtqUsed {
    pub flags: u16,
    pub idx: u16,
    pub ring: [VirtqUsedElem; 0],
}
