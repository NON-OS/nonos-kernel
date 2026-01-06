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
//
/// # Safety applies this rules on all unsafe calls:
/// Caller must ensure:
/// `ptr` is valid and points to allocated memory
/// All accessed indices are within the bitmap bounds

use super::constants::BITS_PER_BYTE;
// ============================================================================
// BITMAP BIT OPERATIONS
// ============================================================================
/// # Safety
#[inline]
pub unsafe fn bit_test(ptr: *mut u8, idx: usize) -> bool {
    // SAFETY: Caller guarantees ptr is valid and idx is in bounds
    let byte = ptr.add(idx / BITS_PER_BYTE).read_volatile();
    (byte & (1u8 << (idx & 7))) != 0
}
/// # Safety
#[inline]
pub unsafe fn bit_set(ptr: *mut u8, idx: usize) {
    // SAFETY: Caller guarantees ptr is valid and idx is in bounds
    let bptr = ptr.add(idx / BITS_PER_BYTE);
    let v = bptr.read_volatile();
    bptr.write_volatile(v | (1u8 << (idx & 7)));
}
/// # Safety
#[inline]
pub unsafe fn bit_clear(ptr: *mut u8, idx: usize) {
    // SAFETY: Caller guarantees ptr is valid and idx is in bounds
    let bptr = ptr.add(idx / BITS_PER_BYTE);
    let v = bptr.read_volatile();
    bptr.write_volatile(v & !(1u8 << (idx & 7)));
}

// ============================================================================
// BITMAP COUNTING
// ============================================================================
/// # Safety
pub unsafe fn count_free_bits(ptr: *mut u8, count: usize) -> usize {
    let mut free = 0usize;
    for i in 0..count {
        // SAFETY: Caller guarantees indices are valid
        if !bit_test(ptr, i) {
            free = free.saturating_add(1);
        }
    }
    free
}
/// # Safety
pub unsafe fn find_first_free(ptr: *mut u8, total: usize, start: usize) -> Option<usize> {
    for offset in 0..total {
        let idx = (start + offset) % total;
        // SAFETY: Caller guarantees indices are valid
        if !bit_test(ptr, idx) {
            return Some(idx);
        }
    }
    None
}
/// # Safety
pub unsafe fn find_contiguous_free(ptr: *mut u8, total: usize, count: usize) -> Option<usize> {
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
}
/// # Safety
pub unsafe fn set_bit_range(ptr: *mut u8, start: usize, count: usize) {
    for i in start..start + count {
        // SAFETY: Caller guarantees indices are valid
        bit_set(ptr, i);
    }
}
/// # Safety
pub unsafe fn clear_bit_range(ptr: *mut u8, start: usize, count: usize) {
    for i in start..start + count {
        // SAFETY: Caller guarantees indices are valid
        bit_clear(ptr, i);
    }
}
/// # Safety
pub unsafe fn is_range_allocated(ptr: *mut u8, start: usize, count: usize) -> bool {
    for i in start..start + count {
        // SAFETY: Caller guarantees indices are valid
        if !bit_test(ptr, i) {
            return false;
        }
    }
    true
}
