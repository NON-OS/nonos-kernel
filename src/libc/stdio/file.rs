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

pub const BUFSIZ: usize = 1024;
pub const EOF: i32 = -1;
pub const SEEK_SET: i32 = 0;
pub const SEEK_CUR: i32 = 1;
pub const SEEK_END: i32 = 2;

#[repr(C)]
pub struct FILE {
    pub fd: i32,
    pub flags: u32,
    pub buf: *mut u8,
    pub buf_size: usize,
    pub buf_pos: usize,
    pub buf_len: usize,
    pub error: i32,
    pub eof: bool,
}

pub const _IONBF: u32 = 0x0004;
pub const _IOLBF: u32 = 0x0040;
pub const _IOFBF: u32 = 0x0000;
pub const _IOREAD: u32 = 0x0001;
pub const _IOWRITE: u32 = 0x0002;

static mut STDIN_FILE: FILE = FILE {
    fd: 0,
    flags: _IOREAD | _IOLBF,
    buf: ptr::null_mut(),
    buf_size: 0,
    buf_pos: 0,
    buf_len: 0,
    error: 0,
    eof: false,
};
static mut STDOUT_FILE: FILE = FILE {
    fd: 1,
    flags: _IOWRITE | _IOLBF,
    buf: ptr::null_mut(),
    buf_size: 0,
    buf_pos: 0,
    buf_len: 0,
    error: 0,
    eof: false,
};
static mut STDERR_FILE: FILE = FILE {
    fd: 2,
    flags: _IOWRITE | _IONBF,
    buf: ptr::null_mut(),
    buf_size: 0,
    buf_pos: 0,
    buf_len: 0,
    error: 0,
    eof: false,
};

#[no_mangle]
pub unsafe extern "C" fn stdin() -> *mut FILE {
    &raw mut STDIN_FILE
}
#[no_mangle]
pub unsafe extern "C" fn stdout() -> *mut FILE {
    &raw mut STDOUT_FILE
}
#[no_mangle]
pub unsafe extern "C" fn stderr() -> *mut FILE {
    &raw mut STDERR_FILE
}

#[no_mangle]
pub unsafe extern "C" fn fflush(stream: *mut FILE) -> i32 {
    if stream.is_null() {
        return 0;
    }
    let f = &mut *stream;
    if (f.flags & _IOWRITE) != 0 && f.buf_pos > 0 && !f.buf.is_null() {
        let written = crate::libc::unistd::write(f.fd, f.buf, f.buf_pos);
        if written < 0 {
            f.error = 1;
            return EOF;
        }
        f.buf_pos = 0;
    }
    0
}

#[no_mangle]
pub unsafe extern "C" fn feof(stream: *mut FILE) -> i32 {
    if stream.is_null() {
        return 0;
    }
    if (*stream).eof {
        1
    } else {
        0
    }
}

#[no_mangle]
pub unsafe extern "C" fn ferror(stream: *mut FILE) -> i32 {
    if stream.is_null() {
        return 0;
    }
    (*stream).error
}

#[no_mangle]
pub unsafe extern "C" fn clearerr(stream: *mut FILE) {
    if stream.is_null() {
        return;
    }
    (*stream).error = 0;
    (*stream).eof = false;
}

#[no_mangle]
pub unsafe extern "C" fn fileno(stream: *mut FILE) -> i32 {
    if stream.is_null() {
        return -1;
    }
    (*stream).fd
}

#[no_mangle]
pub unsafe extern "C" fn setvbuf(stream: *mut FILE, buf: *mut u8, mode: i32, size: usize) -> i32 {
    if stream.is_null() {
        return -1;
    }
    let f = &mut *stream;
    f.flags &= !(_IONBF | _IOLBF | _IOFBF);
    f.flags |= match mode {
        0 => _IOFBF,
        1 => _IOLBF,
        2 => _IONBF,
        _ => return -1,
    };
    if !buf.is_null() {
        f.buf = buf;
        f.buf_size = size;
    }
    0
}
