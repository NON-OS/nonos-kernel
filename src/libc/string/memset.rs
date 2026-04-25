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

use core::ptr;

#[no_mangle]
pub unsafe extern "C" fn memset(dest: *mut u8, c: i32, n: usize) -> *mut u8 {
    if n == 0 || dest.is_null() {
        return dest;
    }
    let b = c as u8;
    let d = dest as usize;
    if d % 8 == 0 && n >= 8 {
        let pattern = (b as u64) * 0x0101010101010101u64;
        let qwords = n / 8;
        let dp = dest as *mut u64;
        for i in 0..qwords {
            ptr::write(dp.add(i), pattern);
        }
        let rem = n % 8;
        let off = qwords * 8;
        for i in 0..rem {
            ptr::write(dest.add(off + i), b);
        }
    } else {
        for i in 0..n {
            ptr::write(dest.add(i), b);
        }
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memcmp(s1: *const u8, s2: *const u8, n: usize) -> i32 {
    if n == 0 {
        return 0;
    }
    for i in 0..n {
        let a = ptr::read(s1.add(i));
        let b = ptr::read(s2.add(i));
        if a != b {
            return (a as i32) - (b as i32);
        }
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn bzero(dest: *mut u8, n: usize) {
    memset(dest, 0, n);
}

#[no_mangle]
pub unsafe extern "C" fn memchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
    let b = c as u8;
    for i in 0..n {
        if ptr::read(s.add(i)) == b {
            return s.add(i) as *mut u8;
        }
    }
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn memrchr(s: *const u8, c: i32, n: usize) -> *mut u8 {
    if n == 0 {
        return ptr::null_mut();
    }
    let b = c as u8;
    for i in (0..n).rev() {
        if ptr::read(s.add(i)) == b {
            return s.add(i) as *mut u8;
        }
    }
    ptr::null_mut()
}
