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

//! 32-bit MMIO accessor over the broker-mapped BAR0 window. The
//! register file is fully 32-bit; `volatile` is required so the
//! compiler does not coalesce reads/writes that the device cares
//! about ordering on. The base is the user_va the broker handed
//! back from `mk_mmio_map`.

use core::ptr;

#[derive(Clone, Copy)]
pub struct Regs {
    base: u64,
}

impl Regs {
    pub const fn new(base: u64) -> Self {
        Self { base }
    }

    /// # Safety
    /// `offset` must be a 4-byte-aligned register the device exposes
    /// in the mapped BAR0 window. eK@nonos.systems — the broker's
    /// `MmioMap` grant guarantees the page is present, user-mapped,
    /// uncached, and read+write; the offset bound is the caller's
    /// responsibility.
    pub unsafe fn r32(&self, offset: usize) -> u32 {
        ptr::read_volatile((self.base as usize + offset) as *const u32)
    }

    /// # Safety
    /// Same conditions as `r32`. eK@nonos.systems — the device may
    /// observe the write any time after the volatile store retires;
    /// callers that need a fence should issue one themselves.
    pub unsafe fn w32(&self, offset: usize, value: u32) {
        ptr::write_volatile((self.base as usize + offset) as *mut u32, value);
    }
}
