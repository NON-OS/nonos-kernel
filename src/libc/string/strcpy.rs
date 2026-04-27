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
pub unsafe extern "C" fn strcpy(dest: *mut u8, src: *const u8) -> *mut u8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let mut i = 0usize;
    loop {
        let c = ptr::read(src.add(i));
        ptr::write(dest.add(i), c);
        if c == 0 {
            break;
        }
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn strncpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dest.is_null() || n == 0 {
        return dest;
    }
    let mut i = 0usize;
    while i < n {
        let c = if src.is_null() { 0 } else { ptr::read(src.add(i)) };
        ptr::write(dest.add(i), c);
        if c == 0 {
            i += 1;
            while i < n {
                ptr::write(dest.add(i), 0);
                i += 1;
            }
            break;
        }
        i += 1;
    }
    dest
}

#[no_mangle]
pub unsafe extern "C" fn strcat(dest: *mut u8, src: *const u8) -> *mut u8 {
    if dest.is_null() || src.is_null() {
        return dest;
    }
    let dlen = super::strlen::strlen(dest);
    strcpy(dest.add(dlen), src);
    dest
}

#[no_mangle]
pub unsafe extern "C" fn strncat(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    if dest.is_null() || src.is_null() || n == 0 {
        return dest;
    }
    let dlen = super::strlen::strlen(dest);
    let slen = super::strlen::strnlen(src, n);
    let copy_len = if slen < n { slen } else { n };
    for i in 0..copy_len {
        ptr::write(dest.add(dlen + i), ptr::read(src.add(i)));
    }
    ptr::write(dest.add(dlen + copy_len), 0);
    dest
}

#[no_mangle]
pub unsafe extern "C" fn strdup(s: *const u8) -> *mut u8 {
    if s.is_null() {
        return ptr::null_mut();
    }
    let len = super::strlen::strlen(s);
    let p = crate::libc::stdlib::malloc(len + 1) as *mut u8;
    if p.is_null() {
        return ptr::null_mut();
    }
    super::memcpy::memcpy(p, s, len + 1);
    p
}

#[no_mangle]
pub unsafe extern "C" fn strndup(s: *const u8, n: usize) -> *mut u8 {
    if s.is_null() {
        return ptr::null_mut();
    }
    let len = super::strlen::strnlen(s, n);
    let p = crate::libc::stdlib::malloc(len + 1) as *mut u8;
    if p.is_null() {
        return ptr::null_mut();
    }
    super::memcpy::memcpy(p, s, len);
    ptr::write(p.add(len), 0);
    p
}
