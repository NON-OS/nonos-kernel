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
pub(in crate::memory::mmio) unsafe fn read8_at(addr: u64) -> u8 {
    unsafe {
        let ptr = addr as *const u8;
        compiler_fence(Ordering::SeqCst);
        let value = ptr::read_volatile(ptr);
        compiler_fence(Ordering::SeqCst);
        MMIO_STATS.record_read();
        value
    }
}

#[inline]
pub(in crate::memory::mmio) unsafe fn read16_at(addr: u64) -> u16 {
    unsafe {
        let ptr = addr as *const u16;
        compiler_fence(Ordering::SeqCst);
        let value = ptr::read_volatile(ptr);
        compiler_fence(Ordering::SeqCst);
        MMIO_STATS.record_read();
        value
    }
}

#[inline]
pub(in crate::memory::mmio) unsafe fn read32_at(addr: u64) -> u32 {
    unsafe {
        let ptr = addr as *const u32;
        compiler_fence(Ordering::SeqCst);
        let value = ptr::read_volatile(ptr);
        compiler_fence(Ordering::SeqCst);
        MMIO_STATS.record_read();
        value
    }
}

#[inline]
pub(in crate::memory::mmio) unsafe fn read64_at(addr: u64) -> u64 {
    unsafe {
        let ptr = addr as *const u64;
        compiler_fence(Ordering::SeqCst);
        let value = ptr::read_volatile(ptr);
        compiler_fence(Ordering::SeqCst);
        MMIO_STATS.record_read();
        value
    }
}
