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

use super::super::constants::BITS_PER_BYTE;

#[inline]
pub(in crate::memory::phys) unsafe fn bit_test(ptr: *mut u8, idx: usize) -> bool {
    unsafe {
        let byte = ptr.add(idx / BITS_PER_BYTE).read_volatile();
        (byte & (1u8 << (idx & 7))) != 0
    }
}

#[inline]
pub(in crate::memory::phys) unsafe fn bit_set(ptr: *mut u8, idx: usize) {
    unsafe {
        let bptr = ptr.add(idx / BITS_PER_BYTE);
        let v = bptr.read_volatile();
        bptr.write_volatile(v | (1u8 << (idx & 7)));
    }
}

#[inline]
pub(in crate::memory::phys) unsafe fn bit_clear(ptr: *mut u8, idx: usize) {
    unsafe {
        let bptr = ptr.add(idx / BITS_PER_BYTE);
        let v = bptr.read_volatile();
        bptr.write_volatile(v & !(1u8 << (idx & 7)));
    }
}
