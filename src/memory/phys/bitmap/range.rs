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

use super::bit_ops::{bit_set, bit_clear, bit_test};

pub(in crate::memory::phys) unsafe fn set_bit_range(ptr: *mut u8, start: usize, count: usize) {
    unsafe {
        for i in start..start + count {
            bit_set(ptr, i);
        }
    }
}

pub(in crate::memory::phys) unsafe fn clear_bit_range(ptr: *mut u8, start: usize, count: usize) {
    unsafe {
        for i in start..start + count {
            bit_clear(ptr, i);
        }
    }
}

pub(in crate::memory::phys) unsafe fn is_range_allocated(
    ptr: *mut u8,
    start: usize,
    count: usize,
) -> bool {
    unsafe {
        for i in start..start + count {
            if !bit_test(ptr, i) {
                return false;
            }
        }
        true
    }
}
