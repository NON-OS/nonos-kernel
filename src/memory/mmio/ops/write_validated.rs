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
use core::sync::atomic::{compiler_fence, Ordering};

#[inline]
pub(in crate::memory::mmio) unsafe fn write8_at(addr: u64, value: u8) {
    unsafe {
        let ptr = addr as *mut u8;
        compiler_fence(Ordering::SeqCst);
        ptr::write_volatile(ptr, value);
        compiler_fence(Ordering::SeqCst);
        MMIO_STATS.record_write();
    }
}

#[inline]
pub(in crate::memory::mmio) unsafe fn write16_at(addr: u64, value: u16) {
    unsafe {
        let ptr = addr as *mut u16;
        compiler_fence(Ordering::SeqCst);
        ptr::write_volatile(ptr, value);
        compiler_fence(Ordering::SeqCst);
        MMIO_STATS.record_write();
    }
}

#[inline]
pub(in crate::memory::mmio) unsafe fn write32_at(addr: u64, value: u32) {
    unsafe {
        let ptr = addr as *mut u32;
        compiler_fence(Ordering::SeqCst);
        ptr::write_volatile(ptr, value);
        compiler_fence(Ordering::SeqCst);
        MMIO_STATS.record_write();
    }
}

#[inline]
pub(in crate::memory::mmio) unsafe fn write64_at(addr: u64, value: u64) {
    unsafe {
        let ptr = addr as *mut u64;
        compiler_fence(Ordering::SeqCst);
        ptr::write_volatile(ptr, value);
        compiler_fence(Ordering::SeqCst);
        MMIO_STATS.record_write();
    }
}
