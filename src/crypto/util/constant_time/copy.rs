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

use core::ptr;

use super::{compiler_fence, volatile_write};
#[inline(never)]
pub fn ct_conditional_move(dst: &mut [u8], src: &[u8], cond: bool) {
    if dst.len() != src.len() {
        return;
    }
    let mask = (-(cond as i8)) as u8;
    for i in 0..dst.len() {
        dst[i] = (mask & src[i]) | (!mask & dst[i]);
    }
    compiler_fence();
}

#[inline(never)]
pub fn ct_conditional_swap(a: &mut [u8], b: &mut [u8], cond: bool) {
    if a.len() != b.len() {
        return;
    }
    let mask = (-(cond as i8)) as u8;
    for i in 0..a.len() {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
    compiler_fence();
}

#[inline(never)]
pub fn ct_conditional_swap_32(a: &mut [u8; 32], b: &mut [u8; 32], cond: bool) {
    let mask = (-(cond as i8)) as u8;
    for i in 0..32 {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
    compiler_fence();
}

#[inline(never)]
pub fn secure_zero(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // # SAFETY: write_volatile ensures the compiler cannot optimize away this
        // write. The pointer is valid because it comes from a mutable reference.
        unsafe { ptr::write_volatile(byte, 0) };
    }
    compiler_fence();
}

#[inline(never)]
pub fn secure_erase(data: &mut [u8]) {
    for byte in data.iter_mut() {
        // # SAFETY: write_volatile prevents optimization. Pointer validity guaranteed
        // by mutable reference from slice iteration.
        unsafe { ptr::write_volatile(byte, 0x00) };
    }
    compiler_fence();

    for byte in data.iter_mut() {
        // # SAFETY: Same as above, volatile write to valid mutable reference.
        unsafe { ptr::write_volatile(byte, 0xFF) };
    }
    compiler_fence();

    for byte in data.iter_mut() {
        // # SAFETY: Same as above, volatile write to valid mutable reference.
        unsafe { ptr::write_volatile(byte, 0x00) };
    }
    compiler_fence();
}

#[inline(never)]
pub fn ct_copy(dst: &mut [u8], src: &[u8]) {
    let len = dst.len().min(src.len());
    for i in 0..len {
        dst[i] = src[i];
    }
    for i in len..dst.len() {
        let val = dst[i];
        volatile_write(&mut dst[i], val);
    }
    compiler_fence();
}
