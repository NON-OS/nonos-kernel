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

extern crate alloc;
use alloc::string::String;
use alloc::vec::Vec;
use core::ptr;
use spin::Mutex;

static ENVIRON: Mutex<Vec<String>> = Mutex::new(Vec::new());
static mut ENVIRON_PTRS: [*const u8; 256] = [ptr::null(); 256];

pub fn environ_ptr() -> *const *const u8 {
    update_environ_ptrs();
    core::ptr::addr_of!(ENVIRON_PTRS) as *const *const u8
}

fn update_environ_ptrs() {
    let env = ENVIRON.lock();
    for (i, s) in env.iter().enumerate() {
        if i >= 255 {
            break;
        }
        unsafe {
            ENVIRON_PTRS[i] = s.as_ptr();
        }
    }
    unsafe {
        ENVIRON_PTRS[env.len().min(255)] = ptr::null();
    }
}

#[no_mangle]
pub unsafe extern "C" fn getenv(name: *const u8) -> *const u8 {
    if name.is_null() {
        return ptr::null();
    }
    let name_len = crate::libc::string::strlen::strlen(name);
    let env = ENVIRON.lock();
    for s in env.iter() {
        let bytes = s.as_bytes();
        if bytes.len() > name_len && bytes[name_len] == b'=' {
            let mut matches = true;
            for i in 0..name_len {
                if bytes[i] != ptr::read(name.add(i)) {
                    matches = false;
                    break;
                }
            }
            if matches {
                return bytes[name_len + 1..].as_ptr();
            }
        }
    }
    ptr::null()
}

#[no_mangle]
pub unsafe extern "C" fn setenv(name: *const u8, value: *const u8, overwrite: i32) -> i32 {
    if name.is_null() {
        crate::libc::errno::set_errno(22);
        return -1;
    }
    let name_len = crate::libc::string::strlen::strlen(name);
    let val_len = if value.is_null() { 0 } else { crate::libc::string::strlen::strlen(value) };
    let mut env = ENVIRON.lock();
    for s in env.iter_mut() {
        let bytes = s.as_bytes();
        if bytes.len() > name_len && bytes[name_len] == b'=' {
            let mut matches = true;
            for i in 0..name_len {
                if bytes[i] != ptr::read(name.add(i)) {
                    matches = false;
                    break;
                }
            }
            if matches {
                if overwrite == 0 {
                    return 0;
                }
                let mut new_s = String::with_capacity(name_len + 1 + val_len);
                for i in 0..name_len {
                    new_s.push(ptr::read(name.add(i)) as char);
                }
                new_s.push('=');
                for i in 0..val_len {
                    new_s.push(ptr::read(value.add(i)) as char);
                }
                *s = new_s;
                return 0;
            }
        }
    }
    let mut new_s = String::with_capacity(name_len + 1 + val_len);
    for i in 0..name_len {
        new_s.push(ptr::read(name.add(i)) as char);
    }
    new_s.push('=');
    for i in 0..val_len {
        new_s.push(ptr::read(value.add(i)) as char);
    }
    env.push(new_s);
    0
}

#[no_mangle]
pub unsafe extern "C" fn unsetenv(name: *const u8) -> i32 {
    if name.is_null() {
        crate::libc::errno::set_errno(22);
        return -1;
    }
    let name_len = crate::libc::string::strlen::strlen(name);
    let mut env = ENVIRON.lock();
    env.retain(|s| {
        let bytes = s.as_bytes();
        if bytes.len() <= name_len || bytes[name_len] != b'=' {
            return true;
        }
        for i in 0..name_len {
            if bytes[i] != ptr::read(name.add(i)) {
                return true;
            }
        }
        false
    });
    0
}

#[no_mangle]
pub unsafe extern "C" fn putenv(string: *mut u8) -> i32 {
    if string.is_null() {
        crate::libc::errno::set_errno(22);
        return -1;
    }
    let len = crate::libc::string::strlen::strlen(string);
    let mut s = String::with_capacity(len);
    for i in 0..len {
        s.push(ptr::read(string.add(i)) as char);
    }
    ENVIRON.lock().push(s);
    0
}
