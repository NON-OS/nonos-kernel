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

use super::super::stats::MMIO_STATS;
use core::ptr;
use crate::memory::addr::VirtAddr;

#[inline]
pub fn mmio_w8(va: VirtAddr, value: u8) {
    MMIO_STATS.record_write();
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

#[inline]
pub fn mmio_w16(va: VirtAddr, value: u16) {
    MMIO_STATS.record_write();
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

#[inline]
pub fn mmio_w32(va: VirtAddr, value: u32) {
    MMIO_STATS.record_write();
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}

#[inline]
pub fn mmio_w64(va: VirtAddr, value: u64) {
    MMIO_STATS.record_write();
    unsafe { ptr::write_volatile(va.as_mut_ptr(), value) }
}
