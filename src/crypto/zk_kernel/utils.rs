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

//! Utility functions for zero-knowledge proofs.

use core::ptr;
use crate::crypto::util::constant_time::{compiler_fence, memory_fence};

/// Securely zero a byte slice with memory barriers.
///
/// Uses volatile writes to ensure the compiler does not optimize away
/// the zeroization, followed by memory barriers to ensure visibility.
#[inline]
pub fn zeroize(buf: &mut [u8]) {
    for b in buf {
        unsafe { ptr::write_volatile(b, 0) };
    }
    compiler_fence();
    memory_fence();
}

/// Constant-time equality check for 32-byte arrays.
#[inline]
pub fn constant_time_eq(a: &[u8; 32], b: &[u8; 32]) -> bool {
    let mut diff = 0u8;
    for i in 0..32 {
        diff |= a[i] ^ b[i];
    }
    diff == 0
}
