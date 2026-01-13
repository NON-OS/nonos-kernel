// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

mod compare;
mod copy;
mod math;
mod select;
#[cfg(test)]
mod tests;

use core::ptr;

pub use compare::{
    ct_eq, ct_eq_16, ct_eq_32, ct_eq_64, ct_eq_u64, ct_gt_u64, ct_is_nonzero_u64, ct_is_zero_u64,
    ct_lt_u64,
};
pub use copy::{
    ct_conditional_move, ct_conditional_swap, ct_conditional_swap_32, ct_copy, secure_erase,
    secure_zero,
};
pub use math::{
    ct_add_overflow_u64, ct_add_u64, ct_bswap_u32, ct_bswap_u64, ct_clz_u64, ct_conditional_negate,
    ct_mod_u64, ct_mul_u64, ct_popcount_u64, ct_sub_u64,
};
pub use select::{
    ct_select_u16, ct_select_u32, ct_select_u64, ct_select_u64_bit, ct_select_u8, ct_select_usize,
};

#[inline(always)]
pub fn compiler_fence() {
    // # SAFETY: Empty inline assembly with memory clobber acts as a compiler barrier.
    // # The absence of nomem forces the compiler to assume memory may be accessed,
    // # preventing reordering of memory operations across this barrier.
    unsafe {
        core::arch::asm!("", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn memory_fence() {
    // # SAFETY: MFENCE is a serializing memory instruction on x86-64 that ensures
    // # all memory loads and stores before the fence are globally visible before
    // # any loads or stores after it. No nomem  memory operations must not cross this barrier.
    unsafe {
        core::arch::asm!("mfence", options(nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn serialize_execution() {
    // # SAFETY: LFENCE ensures all prior load instructions complete before any
    // # subsequent instructions execute. This prevents speculative execution from
    // # bypassing the barrier. No nomem memory operations must not cross this barrier.
    unsafe {
        core::arch::asm!("lfence", options(nostack, preserves_flags));
    }
}

#[inline(never)]
pub fn volatile_read<T: Copy>(val: &T) -> T {
    // # SAFETY: read_volatile ensures the compiler cannot optimize away this read.
    // # The pointer is valid because it comes from a shared reference.
    unsafe { ptr::read_volatile(val) }
}

#[inline(never)]
pub fn volatile_write<T>(dst: &mut T, val: T) {
    // # SAFETY: write_volatile ensures the compiler cannot optimize away this write.
    // # The pointer is valid because it comes from a mutable reference.
    unsafe { ptr::write_volatile(dst, val) };
}

#[inline(never)]
pub fn ct_lookup_u8(table: &[u8; 256], index: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..256 {
        let eq = ct_eq_u8(i as u8, index);
        let mask = (-(eq as i8)) as u8;
        result |= mask & table[i];
    }
    compiler_fence();
    result
}

#[inline(always)]
fn ct_eq_u8(a: u8, b: u8) -> u8 {
    let diff = a ^ b;
    let is_zero = diff | diff.wrapping_neg();
    1 ^ ((is_zero >> 7) & 1)
}

#[inline(never)]
pub fn ct_lookup_u8_16(table: &[u8; 16], index: u8) -> u8 {
    let mut result: u8 = 0;
    for i in 0..16 {
        let eq = ct_eq_u8(i as u8, index);
        let mask = (-(eq as i8)) as u8;
        result |= mask & table[i];
    }
    compiler_fence();
    result
}

#[inline(always)]
fn ct_eq_usize(a: usize, b: usize) -> u32 {
    let diff = a ^ b;
    let is_zero = (diff | diff.wrapping_neg()) as u64;
    1 ^ (((is_zero >> 63) & 1) as u32)
}

#[inline(never)]
pub fn ct_lookup_u32(table: &[u32], index: usize) -> u32 {
    let mut result: u32 = 0;
    for i in 0..table.len() {
        let eq = ct_eq_usize(i, index);
        let mask = 0u32.wrapping_sub(eq);
        result |= mask & table[i];
    }
    compiler_fence();
    result
}

#[inline(never)]
pub fn ct_is_zero_slice(data: &[u8]) -> bool {
    let mut acc: u8 = 0;
    for &byte in data {
        acc |= byte;
    }
    compiler_fence();
    acc == 0
}

#[inline(never)]
pub fn ct_is_nonzero_slice(data: &[u8]) -> bool {
    !ct_is_zero_slice(data)
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
