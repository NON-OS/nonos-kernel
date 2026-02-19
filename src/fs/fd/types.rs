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

use alloc::{string::String, vec::Vec};

use super::error::{FdError, FdResult};

pub const MAX_FD: i32 = 4096;
pub const MAX_PATH_LEN: usize = 4096;
pub const MAX_COPY_SIZE: usize = 8 * 1024 * 1024;
pub const RESERVED_FDS: i32 = 3;

pub const O_RDONLY: i32 = 0o000000;
pub const O_WRONLY: i32 = 0o000001;
pub const O_RDWR: i32 = 0o000002;
pub const O_APPEND: i32 = 0o0002000;
pub const O_CREAT: i32 = 0o0000100;
pub const O_TRUNC: i32 = 0o0001000;
pub const O_NONBLOCK: i32 = 0o0004000;
pub const O_CLOEXEC: i32 = 0o2000000;

pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

#[derive(Debug, Clone)]
pub struct OpenFile {
    pub path: String,
    pub offset: usize,
    pub flags: i32,
    pub cloexec: bool,
}

impl OpenFile {
    pub fn new(path: String, flags: i32) -> Self {
        let cloexec = (flags & O_CLOEXEC) != 0;
        Self {
            path,
            offset: 0,
            flags: flags & !O_CLOEXEC,
            cloexec,
        }
    }

    #[inline]
    pub fn is_readable(&self) -> bool {
        (self.flags & O_WRONLY) == 0
    }

    #[inline]
    pub fn is_writable(&self) -> bool {
        (self.flags & O_WRONLY) != 0 || (self.flags & O_RDWR) != 0
    }

    #[inline]
    pub fn is_append(&self) -> bool {
        (self.flags & O_APPEND) != 0
    }

    #[inline]
    pub fn is_nonblocking(&self) -> bool {
        (self.flags & O_NONBLOCK) != 0
    }
}

// ## SAFETY: Caller must ensure `src` points to valid memory of at least `len` bytes.
#[inline]
pub unsafe fn copy_from_user_ptr(src: *const u8, dst: &mut [u8]) -> FdResult<usize> { unsafe {
    if src.is_null() {
        return Err(FdError::NullPointer);
    }
    let len = dst.len();
    if len > MAX_COPY_SIZE {
        return Err(FdError::BufferTooLarge);
    }
    core::ptr::copy_nonoverlapping(src, dst.as_mut_ptr(), len);
    Ok(len)
}}

// ## SAFETY: Caller must ensure `dst` points to valid writable memory of at least `src.len()` bytes.
#[inline]
pub unsafe fn copy_to_user_ptr(src: &[u8], dst: *mut u8) -> FdResult<usize> { unsafe {
    if dst.is_null() {
        return Err(FdError::NullPointer);
    }
    let len = src.len();
    if len > MAX_COPY_SIZE {
        return Err(FdError::BufferTooLarge);
    }
    core::ptr::copy_nonoverlapping(src.as_ptr(), dst, len);
    Ok(len)
}}

// ## SAFETY: Caller must ensure `ptr` points to valid readable memory.
#[inline]
pub unsafe fn read_user_byte(ptr: *const u8) -> FdResult<u8> { unsafe {
    if ptr.is_null() {
        return Err(FdError::NullPointer);
    }
    Ok(core::ptr::read(ptr))
}}

// ## SAFETY: Caller must ensure `ptr` points to valid writable memory.
#[inline]
pub unsafe fn write_user_byte(ptr: *mut u8, value: u8) -> FdResult<()> { unsafe {
    if ptr.is_null() {
        return Err(FdError::NullPointer);
    }
    core::ptr::write(ptr, value);
    Ok(())
}}

pub fn cstr_to_string(ptr: *const u8) -> FdResult<String> {
    if ptr.is_null() {
        return Err(FdError::NullPointer);
    }

    let mut bytes: Vec<u8> = Vec::with_capacity(256);
    let mut off = 0usize;

    loop {
        // ## Safety: We check null above, and bounds below
        let b = unsafe { core::ptr::read(ptr.add(off)) };
        if b == 0 {
            break;
        }
        bytes.push(b);
        off += 1;
        if off > MAX_PATH_LEN {
            return Err(FdError::PathTooLong);
        }
    }

    core::str::from_utf8(&bytes)
        .map(|s| s.into())
        .map_err(|_| FdError::InvalidUtf8)
}
