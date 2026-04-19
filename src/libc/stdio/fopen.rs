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
use super::file::{FILE, _IOREAD, _IOWRITE, _IOLBF, EOF};

#[no_mangle]
pub unsafe extern "C" fn fopen(path: *const u8, mode: *const u8) -> *mut FILE {
    if path.is_null() || mode.is_null() { return ptr::null_mut(); }
    let (flags, oflag) = parse_mode(mode);
    let fd = crate::syscall::sys_open(path as u64, oflag as u64, 0o644);
    if fd < 0 { return ptr::null_mut(); }
    let f = crate::libc::stdlib::malloc::malloc(core::mem::size_of::<FILE>()) as *mut FILE;
    if f.is_null() { crate::libc::unistd::close(fd as i32); return ptr::null_mut(); }
    ptr::write(f, FILE { fd: fd as i32, flags, buf: ptr::null_mut(), buf_size: 0, buf_pos: 0, buf_len: 0, error: 0, eof: false });
    f
}

fn parse_mode(mode: *const u8) -> (u32, i32) {
    let mut flags = 0u32;
    let mut oflag = 0i32;
    unsafe {
        let c0 = ptr::read(mode);
        match c0 {
            b'r' => { flags |= _IOREAD; oflag = 0; }
            b'w' => { flags |= _IOWRITE; oflag = 0x41 | 0x200; }
            b'a' => { flags |= _IOWRITE; oflag = 0x41 | 0x400; }
            _ => {}
        }
        let c1 = ptr::read(mode.add(1));
        if c1 == b'+' { flags |= _IOREAD | _IOWRITE; oflag = 2; }
    }
    flags |= _IOLBF;
    (flags, oflag)
}

#[no_mangle]
pub unsafe extern "C" fn fclose(stream: *mut FILE) -> i32 {
    if stream.is_null() { return EOF; }
    super::file::fflush(stream);
    let ret = crate::libc::unistd::close((*stream).fd);
    crate::libc::stdlib::free::free(stream as *mut u8);
    ret
}

#[no_mangle]
pub unsafe extern "C" fn fread(ptr: *mut u8, size: usize, nmemb: usize, stream: *mut FILE) -> usize {
    if stream.is_null() || ptr.is_null() || size == 0 || nmemb == 0 { return 0; }
    let total = size * nmemb;
    let n = crate::libc::unistd::read((*stream).fd, ptr, total);
    if n < 0 { (*stream).error = 1; return 0; }
    if n == 0 { (*stream).eof = true; }
    (n as usize) / size
}

#[no_mangle]
pub unsafe extern "C" fn fwrite(ptr: *const u8, size: usize, nmemb: usize, stream: *mut FILE) -> usize {
    if stream.is_null() || ptr.is_null() || size == 0 || nmemb == 0 { return 0; }
    let total = size * nmemb;
    let n = crate::libc::unistd::write((*stream).fd, ptr, total);
    if n < 0 { (*stream).error = 1; return 0; }
    (n as usize) / size
}

#[no_mangle]
pub unsafe extern "C" fn fseek(stream: *mut FILE, offset: i64, whence: i32) -> i32 {
    if stream.is_null() { return -1; }
    let r = crate::syscall::sys_lseek((*stream).fd as u64, offset as u64, whence as u64);
    if r < 0 { -1 } else { (*stream).eof = false; 0 }
}

#[no_mangle]
pub unsafe extern "C" fn ftell(stream: *mut FILE) -> i64 {
    if stream.is_null() { return -1; }
    crate::syscall::sys_lseek((*stream).fd as u64, 0, 1)
}

#[no_mangle]
pub unsafe extern "C" fn rewind(stream: *mut FILE) {
    if !stream.is_null() { fseek(stream, 0, 0); (*stream).error = 0; }
}

#[no_mangle]
pub unsafe extern "C" fn fgetc(stream: *mut FILE) -> i32 {
    if stream.is_null() { return EOF; }
    let mut c = 0u8;
    let n = crate::libc::unistd::read((*stream).fd, &mut c, 1);
    if n <= 0 { if n == 0 { (*stream).eof = true; } else { (*stream).error = 1; } return EOF; }
    c as i32
}

#[no_mangle]
pub unsafe extern "C" fn fputc(c: i32, stream: *mut FILE) -> i32 {
    if stream.is_null() { return EOF; }
    let b = c as u8;
    let n = crate::libc::unistd::write((*stream).fd, &b, 1);
    if n < 0 { (*stream).error = 1; return EOF; }
    c
}

#[no_mangle]
pub unsafe extern "C" fn fgets(s: *mut u8, size: i32, stream: *mut FILE) -> *mut u8 {
    if s.is_null() || size <= 0 || stream.is_null() { return ptr::null_mut(); }
    let mut i = 0;
    while i < (size - 1) as usize {
        let c = fgetc(stream);
        if c == EOF { if i == 0 { return ptr::null_mut(); } break; }
        ptr::write(s.add(i), c as u8); i += 1;
        if c == b'\n' as i32 { break; }
    }
    ptr::write(s.add(i), 0);
    s
}

#[no_mangle]
pub unsafe extern "C" fn fputs(s: *const u8, stream: *mut FILE) -> i32 {
    if s.is_null() || stream.is_null() { return EOF; }
    let len = crate::libc::string::strlen::strlen(s);
    let n = crate::libc::unistd::write((*stream).fd, s, len);
    if n < 0 { EOF } else { 0 }
}

#[no_mangle]
pub unsafe extern "C" fn puts(s: *const u8) -> i32 {
    if s.is_null() { return EOF; }
    let len = crate::libc::string::strlen::strlen(s);
    let n = crate::libc::unistd::write(1, s, len);
    if n < 0 { return EOF; }
    let newline = b"\n";
    crate::libc::unistd::write(1, newline.as_ptr(), 1);
    0
}
