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

use core::sync::atomic::{compiler_fence, Ordering};

#[inline(always)]
pub fn volatile_write_u8(ptr: *mut u8, value: u8) {
    // SAFETY: caller ensures ptr is valid
    unsafe { core::ptr::write_volatile(ptr, value); }
}

#[inline(always)]
pub fn volatile_write_u64(ptr: *mut u64, value: u64) {
    // SAFETY: caller ensures ptr is valid and aligned
    unsafe { core::ptr::write_volatile(ptr, value); }
}

#[inline(always)]
pub fn volatile_read_u8(ptr: *const u8) -> u8 {
    // SAFETY: caller ensures ptr is valid
    unsafe { core::ptr::read_volatile(ptr) }
}

#[inline(always)]
pub fn memory_fence() {
    compiler_fence(Ordering::SeqCst);
    #[cfg(target_arch = "x86_64")]
    // SAFETY: mfence is always safe to execute
    unsafe {
        core::arch::asm!("mfence", options(nomem, nostack, preserves_flags));
    }
}
