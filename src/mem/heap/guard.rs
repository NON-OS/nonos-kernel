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

use core::sync::atomic::{AtomicU64, Ordering};

const GUARD_MAGIC: u64 = 0xDEAD_BEEF_CAFE_BABE;
const GUARD_SIZE: usize = 16;

/// # Safety
/// Guard pages track heap boundaries. Writing to guard pages indicates
/// heap corruption or buffer overflow. These are checked on free.
pub(super) static HEAP_GUARD_LOW: AtomicU64 = AtomicU64::new(0);
pub(super) static HEAP_GUARD_HIGH: AtomicU64 = AtomicU64::new(0);

/// # Safety
/// Writes guard pattern at address. Used to mark heap boundaries.
pub(super) fn write_guard(addr: usize) {
    if addr == 0 {
        return;
    }
    let ptr = addr as *mut u64;
    for i in 0..(GUARD_SIZE / 8) {
        unsafe {
            core::ptr::write_volatile(ptr.add(i), GUARD_MAGIC);
        }
    }
}

/// # Safety
/// Verifies guard pattern is intact. Returns false if corrupted.
pub(super) fn verify_guard(addr: usize) -> bool {
    if addr == 0 {
        return true;
    }
    let ptr = addr as *const u64;
    for i in 0..(GUARD_SIZE / 8) {
        let val = unsafe { core::ptr::read_volatile(ptr.add(i)) };
        if val != GUARD_MAGIC {
            return false;
        }
    }
    true
}

/// # Safety
/// Checks both heap guards. Halts system if either is corrupted.
pub(super) fn check_heap_guards() {
    let low = HEAP_GUARD_LOW.load(Ordering::Relaxed) as usize;
    let high = HEAP_GUARD_HIGH.load(Ordering::Relaxed) as usize;

    if low != 0 && !verify_guard(low) {
        crate::sys::serial::println(b"[FATAL] HEAP CORRUPTION: low guard corrupted");
        crate::arch::x86_64::boot::cpu_ops::halt_loop();
    }
    if high != 0 && !verify_guard(high) {
        crate::sys::serial::println(b"[FATAL] HEAP CORRUPTION: high guard corrupted");
        crate::arch::x86_64::boot::cpu_ops::halt_loop();
    }
}

/// # Safety
/// Validates allocation is within heap bounds.
pub(super) fn validate_heap_ptr(ptr: usize, heap_start: usize, heap_end: usize) -> bool {
    ptr >= heap_start && ptr < heap_end
}
