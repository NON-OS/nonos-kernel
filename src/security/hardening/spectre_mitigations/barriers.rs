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

#[inline(always)]
pub fn lfence() {
    // SAFETY: LFENCE is always safe to execute.
    unsafe {
        core::arch::asm!("lfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn mfence() {
    // SAFETY: MFENCE is always safe to execute.
    unsafe {
        core::arch::asm!("mfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn sfence() {
    // SAFETY: SFENCE is always safe to execute.
    unsafe {
        core::arch::asm!("sfence", options(nomem, nostack, preserves_flags));
    }
}

#[inline(always)]
pub fn array_index_mask_nospec(index: usize, size: usize) -> usize {
    let diff = index.wrapping_sub(size);
    let mask = (diff as isize >> 63) as usize;

    lfence();

    index & mask
}

#[inline(always)]
pub fn array_access_nospec<T: Copy + Default>(array: &[T], index: usize) -> T {
    let safe_index = array_index_mask_nospec(index, array.len());
    if index < array.len() {
        array[safe_index]
    } else {
        T::default()
    }
}
