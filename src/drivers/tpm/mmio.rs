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

//! TPM MMIO Access Functions

use core::sync::atomic::Ordering;

#[inline(always)]
pub(super) unsafe fn mmio_read8(addr: u64) -> u8 { unsafe {
    core::sync::atomic::fence(Ordering::SeqCst);
    let ptr = addr as *const u8;
    let val = core::ptr::read_volatile(ptr);
    core::sync::atomic::fence(Ordering::SeqCst);
    val
}}

#[inline(always)]
pub(super) unsafe fn mmio_write8(addr: u64, val: u8) { unsafe {
    core::sync::atomic::fence(Ordering::SeqCst);
    let ptr = addr as *mut u8;
    core::ptr::write_volatile(ptr, val);
    core::sync::atomic::fence(Ordering::SeqCst);
}}

#[inline(always)]
pub(super) unsafe fn mmio_read32(addr: u64) -> u32 { unsafe {
    core::sync::atomic::fence(Ordering::SeqCst);
    let ptr = addr as *const u32;
    let val = core::ptr::read_volatile(ptr);
    core::sync::atomic::fence(Ordering::SeqCst);
    val
}}

#[inline(always)]
pub(super) unsafe fn mmio_write32(addr: u64, val: u32) { unsafe {
    core::sync::atomic::fence(Ordering::SeqCst);
    let ptr = addr as *mut u32;
    core::ptr::write_volatile(ptr, val);
    core::sync::atomic::fence(Ordering::SeqCst);
}}

#[inline(always)]
pub(super) fn spin_delay(iterations: usize) {
    for _ in 0..iterations {
        core::hint::spin_loop();
    }
}

#[inline(always)]
pub(super) fn delay_ms(ms: u32) {
    for _ in 0..ms {
        spin_delay(10000);
    }
}
