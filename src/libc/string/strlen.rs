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

const MAX_STRLEN: usize = 1 << 20;

#[no_mangle]
pub unsafe extern "C" fn strlen(s: *const u8) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0usize;
    while len < MAX_STRLEN && ptr::read(s.add(len)) != 0 {
        len += 1;
    }
    len
}

#[no_mangle]
pub unsafe extern "C" fn strnlen(s: *const u8, maxlen: usize) -> usize {
    if s.is_null() {
        return 0;
    }
    let mut len = 0usize;
    while len < maxlen && ptr::read(s.add(len)) != 0 {
        len += 1;
    }
    len
}

#[no_mangle]
pub unsafe extern "C" fn strchr(s: *const u8, c: i32) -> *mut u8 {
    if s.is_null() {
        return ptr::null_mut();
    }
    let b = c as u8;
    let mut p = s;
    loop {
        let ch = ptr::read(p);
        if ch == b {
            return p as *mut u8;
        }
        if ch == 0 {
            return ptr::null_mut();
        }
        p = p.add(1);
    }
}

#[no_mangle]
pub unsafe extern "C" fn strrchr(s: *const u8, c: i32) -> *mut u8 {
    if s.is_null() {
        return ptr::null_mut();
    }
    let b = c as u8;
    let len = strlen(s);
    for i in (0..=len).rev() {
        if ptr::read(s.add(i)) == b {
            return s.add(i) as *mut u8;
        }
    }
    ptr::null_mut()
}

#[no_mangle]
pub unsafe extern "C" fn strstr(haystack: *const u8, needle: *const u8) -> *mut u8 {
    if haystack.is_null() {
        return ptr::null_mut();
    }
    if needle.is_null() || ptr::read(needle) == 0 {
        return haystack as *mut u8;
    }
    let nlen = strlen(needle);
    let hlen = strlen(haystack);
    if nlen > hlen {
        return ptr::null_mut();
    }
    for i in 0..=(hlen - nlen) {
        let mut found = true;
        for j in 0..nlen {
            if ptr::read(haystack.add(i + j)) != ptr::read(needle.add(j)) {
                found = false;
                break;
            }
        }
        if found {
            return haystack.add(i) as *mut u8;
        }
    }
    ptr::null_mut()
}
