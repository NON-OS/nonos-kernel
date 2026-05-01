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

use crate::memory::addr::PhysAddr;

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(transparent)]
pub struct Frame(pub u64);

impl Frame {
    #[inline]
    pub const fn new(addr: u64) -> Self {
        Self(addr)
    }

    #[inline]
    pub const fn addr(&self) -> u64 {
        self.0
    }

    #[inline]
    pub fn as_phys_addr(&self) -> PhysAddr {
        PhysAddr::new(self.0)
    }

    #[inline]
    pub fn from_phys_addr(addr: PhysAddr) -> Self {
        Self(addr.as_u64())
    }

    #[inline]
    pub const fn number(&self, base: u64, page_size: u64) -> u64 {
        if self.0 < base {
            0
        } else {
            (self.0 - base) / page_size
        }
    }

    #[inline]
    pub const fn is_null(&self) -> bool {
        self.0 == 0
    }
}

pub type PhysFrame = Frame;
