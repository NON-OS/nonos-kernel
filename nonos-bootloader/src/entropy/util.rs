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

use core::sync::atomic::{compiler_fence, Ordering};

#[inline(always)]
pub fn scrub(b: &mut [u8]) {
    for x in b.iter_mut() {
        compiler_fence(Ordering::SeqCst);
        unsafe {
            core::ptr::write_volatile(x, 0);
        }
    }
    compiler_fence(Ordering::SeqCst);
}

#[inline(always)]
pub fn is_weak_entropy(buf: &[u8; 64]) -> bool {
    let all_zero = buf.iter().all(|&b| b == 0);
    if all_zero {
        return true;
    }

    let half = &buf[0..32];
    half == &buf[32..64]
}
