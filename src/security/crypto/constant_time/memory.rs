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
use super::core::ct_compare;

#[inline(never)]
pub fn ct_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // SAFETY: byte is a valid mutable reference from the slice
        unsafe { core::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline(never)]
pub fn ct_zero_u64(data: &mut [u64]) {
    for word in data.iter_mut() {
        // SAFETY: word is a valid mutable reference from the slice
        unsafe { core::ptr::write_volatile(word, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline(never)]
pub fn ct_hmac_verify(computed: &[u8; 32], expected: &[u8; 32]) -> bool {
    ct_compare(computed, expected)
}

#[inline(never)]
pub fn ct_signature_verify(computed: &[u8; 64], expected: &[u8; 64]) -> bool {
    ct_compare(computed, expected)
}
