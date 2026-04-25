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
pub unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if n == 0 || dest.is_null() || src.is_null() {
        return dest;
    }
    let d = dest as usize;
    let s = src as usize;
    if d % 8 == 0 && s % 8 == 0 && n >= 8 {
        let qwords = n / 8;
        let dp = dest as *mut u64;
        let sp = src as *const u64;
        for i in 0..qwords {
            ptr::write(dp.add(i), ptr::read(sp.add(i)));
        }
        let rem = n % 8;
        let off = qwords * 8;
        for i in 0..rem {
            ptr::write(dest.add(off + i), ptr::read(src.add(off + i)));
        }
    } else {
        for i in 0..n {
            ptr::write(dest.add(i), ptr::read(src.add(i)));
        }
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn memmove(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if n == 0 || dest.is_null() || src.is_null() {
        return dest;
    }
    let d = dest as usize;
    let s = src as usize;
    if d == s {
        return dest;
    }
    if d < s || d >= s + n {
        memcpy(dest, src, n);
    } else {
        for i in (0..n).rev() {
            ptr::write(dest.add(i), ptr::read(src.add(i)));
        }
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn mempcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    memcpy(dest, src, n);
    dest.add(n)
}
