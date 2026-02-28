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

use core::ptr;

#[inline(always)]
pub fn compiler_fence() {
    // SAFETY: Empty inline assembly with memory clobber acts as a compiler barrier.
    unsafe {
        core::arch::asm!("", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn memory_fence() {
    // SAFETY: MFENCE is a serializing memory instruction on x86-64.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn serialize_execution() {
    // SAFETY: LFENCE ensures all prior load instructions complete before subsequent instructions.
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags));
    }
}

#[inline(never)]
pub fn volatile_read<T: Copy>(val: &T) -> T {
    // SAFETY: read_volatile ensures the compiler cannot optimize away this read.
    unsafe { ptr::read_volatile(val) }
}

#[inline(never)]
pub fn volatile_write<T>(dst: &mut T, val: T) {
    // SAFETY: write_volatile ensures the compiler cannot optimize away this write.
    unsafe { ptr::write_volatile(dst, val) };
}

#[inline(never)]
pub fn black_box<T>(val: T) -> T {
    let val = core::hint::black_box(val);
    compiler_fence();
    val
}

#[inline(never)]
pub fn black_box_slice(slice: &[u8]) {
    for byte in slice {
        let _ = volatile_read(byte);
    }
}

#[inline(never)]
pub fn dummy_work(iterations: usize) {
    let mut dummy: u64 = 0;
    for i in 0..iterations {
        dummy = dummy.wrapping_add(i as u64);
        compiler_fence();
    }
    volatile_read(&dummy);
}

#[inline(never)]
pub fn time_constant_execute<F, R>(f: F, dummy_iterations: usize) -> R
where
    F: FnOnce() -> R,
{
    let result = f();
    dummy_work(dummy_iterations);
    result
}
