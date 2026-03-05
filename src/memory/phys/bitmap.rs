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

//! Bitmap Operations for Physical Frame Tracking
//!
//! Provides low-level bitmap manipulation for tracking allocated frames.

use super::constants::BITS_PER_BYTE;

// ============================================================================
// BITMAP BIT OPERATIONS
// ============================================================================

/// Tests if a bit is set in the bitmap.
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - `idx / 8` is within the bitmap bounds
#[inline]
pub(super) unsafe fn bit_test(ptr: *mut u8, idx: usize) -> bool { unsafe {
    // SAFETY: Caller guarantees ptr is valid and idx is in bounds
    let byte = ptr.add(idx / BITS_PER_BYTE).read_volatile();
    (byte & (1u8 << (idx & 7))) != 0
}}

/// Sets a bit in the bitmap (marks frame as allocated).
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - `idx / 8` is within the bitmap bounds
#[inline]
pub(super) unsafe fn bit_set(ptr: *mut u8, idx: usize) { unsafe {
    // SAFETY: Caller guarantees ptr is valid and idx is in bounds
    let bptr = ptr.add(idx / BITS_PER_BYTE);
    let v = bptr.read_volatile();
    bptr.write_volatile(v | (1u8 << (idx & 7)));
}}

/// Clears a bit in the bitmap (marks frame as free).
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - `idx / 8` is within the bitmap bounds
#[inline]
pub(super) unsafe fn bit_clear(ptr: *mut u8, idx: usize) { unsafe {
    // SAFETY: Caller guarantees ptr is valid and idx is in bounds
    let bptr = ptr.add(idx / BITS_PER_BYTE);
    let v = bptr.read_volatile();
    bptr.write_volatile(v & !(1u8 << (idx & 7)));
}}

// ============================================================================
// BITMAP COUNTING
// ============================================================================

/// Counts free bits (zeros) in a bitmap range.
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - All accessed indices are within the bitmap bounds
pub(super) unsafe fn count_free_bits(ptr: *mut u8, count: usize) -> usize { unsafe {
    let mut free = 0usize;
    for i in 0..count {
        // SAFETY: Caller guarantees indices are valid
        if !bit_test(ptr, i) {
            free = free.saturating_add(1);
        }
    }
    free
}}

/// Finds first free bit starting from a given index.
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - All accessed indices are within the bitmap bounds
///
/// # Returns
///
/// Index of first free bit, or None if all bits are set.
pub(super) unsafe fn find_first_free(ptr: *mut u8, total: usize, start: usize) -> Option<usize> { unsafe {
    for offset in 0..total {
        let idx = (start + offset) % total;
        // SAFETY: Caller guarantees indices are valid
        if !bit_test(ptr, idx) {
            return Some(idx);
        }
    }
    None
}}

/// Finds a contiguous run of free bits.
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - All accessed indices are within the bitmap bounds
///
/// # Returns
///
/// Starting index of the run, or None if not found.
pub(super) unsafe fn find_contiguous_free(ptr: *mut u8, total: usize, count: usize) -> Option<usize> { unsafe {
    if count == 0 || count > total {
        return None;
    }

    let mut run_start = 0usize;
    let mut run_length = 0usize;

    for i in 0..total {
        // SAFETY: Caller guarantees indices are valid
        if !bit_test(ptr, i) {
            if run_length == 0 {
                run_start = i;
            }
            run_length += 1;

            if run_length >= count {
                return Some(run_start);
            }
        } else {
            run_length = 0;
        }
    }

    None
}}

/// Sets a range of bits in the bitmap.
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - All accessed indices are within the bitmap bounds
pub(super) unsafe fn set_bit_range(ptr: *mut u8, start: usize, count: usize) { unsafe {
    for i in start..start + count {
        // SAFETY: Caller guarantees indices are valid
        bit_set(ptr, i);
    }
}}

/// Clears a range of bits in the bitmap.
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - All accessed indices are within the bitmap bounds
pub(super) unsafe fn clear_bit_range(ptr: *mut u8, start: usize, count: usize) { unsafe {
    for i in start..start + count {
        // SAFETY: Caller guarantees indices are valid
        bit_clear(ptr, i);
    }
}}

/// Checks if a range of bits are all set (allocated).
///
/// # Safety
///
/// Caller must ensure:
/// - `ptr` is valid and points to allocated memory
/// - All accessed indices are within the bitmap bounds
pub(super) unsafe fn is_range_allocated(ptr: *mut u8, start: usize, count: usize) -> bool { unsafe {
    for i in start..start + count {
        // SAFETY: Caller guarantees indices are valid
        if !bit_test(ptr, i) {
            return false;
        }
    }
    true
}}
