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
use super::file::FILE;

macro_rules! do_format {
    ($buf:expr, $max:expr, $fmt:expr, $args:expr) => {{
        let mut pos = 0usize;
        let mut i = 0usize;
        let buf = $buf;
        let max = $max;
        let fmt = $fmt;
        unsafe {
            while ptr::read(fmt.add(i)) != 0 && pos < max && pos < buf.len() {
                let c = ptr::read(fmt.add(i));
                if c == b'%' {
                    i += 1;
                    let spec = ptr::read(fmt.add(i));
                    match spec {
                        b'd' | b'i' => { let v: i32 = $args.arg(); pos += int_to_str(v as i64, 10, &mut buf[pos..]); }
                        b'u' => { let v: u32 = $args.arg(); pos += uint_to_str(v as u64, 10, &mut buf[pos..]); }
                        b'x' => { let v: u32 = $args.arg(); pos += uint_to_str(v as u64, 16, &mut buf[pos..]); }
                        b'X' => { let v: u32 = $args.arg(); pos += uint_to_str(v as u64, 16, &mut buf[pos..]); }
                        b'p' => { let v: usize = $args.arg(); if pos + 2 < buf.len() { buf[pos] = b'0'; buf[pos+1] = b'x'; pos += 2; pos += uint_to_str(v as u64, 16, &mut buf[pos..]); } }
                        b's' => { let s: *const u8 = $args.arg(); if !s.is_null() { let mut j = 0; while ptr::read(s.add(j)) != 0 && pos < max { buf[pos] = ptr::read(s.add(j)); pos += 1; j += 1; } } }
                        b'c' => { let c: i32 = $args.arg(); buf[pos] = c as u8; pos += 1; }
                        b'%' => { buf[pos] = b'%'; pos += 1; }
                        b'l' => { i += 1; let s2 = ptr::read(fmt.add(i)); match s2 { b'd' => { let v: i64 = $args.arg(); pos += int_to_str(v, 10, &mut buf[pos..]); } b'u' => { let v: u64 = $args.arg(); pos += uint_to_str(v, 10, &mut buf[pos..]); } b'x' => { let v: u64 = $args.arg(); pos += uint_to_str(v, 16, &mut buf[pos..]); } _ => {} } }
                        _ => {}
                    }
                } else { buf[pos] = c; pos += 1; }
                i += 1;
            }
        }
        pos
    }};
}

#[no_mangle]
pub unsafe extern "C" fn printf(fmt: *const u8, mut args: ...) -> i32 {
    let mut buf = [0u8; 4096];
    let len = do_format!(&mut buf, usize::MAX, fmt, args);
    let written = crate::libc::unistd::write(1, buf.as_ptr(), len);
    if written < 0 { -1 } else { written as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn fprintf(stream: *mut FILE, fmt: *const u8, mut args: ...) -> i32 {
    if stream.is_null() { return -1; }
    let mut buf = [0u8; 4096];
    let len = do_format!(&mut buf, usize::MAX, fmt, args);
    let written = crate::libc::unistd::write((*stream).fd, buf.as_ptr(), len);
    if written < 0 { -1 } else { written as i32 }
}

#[no_mangle]
pub unsafe extern "C" fn sprintf(out: *mut u8, fmt: *const u8, mut args: ...) -> i32 {
    if out.is_null() { return -1; }
    let mut temp = [0u8; 4096];
    let len = do_format!(&mut temp, usize::MAX, fmt, args);
    ptr::copy_nonoverlapping(temp.as_ptr(), out, len);
    ptr::write(out.add(len), 0);
    len as i32
}

#[no_mangle]
pub unsafe extern "C" fn snprintf(out: *mut u8, size: usize, fmt: *const u8, mut args: ...) -> i32 {
    if out.is_null() || size == 0 { return 0; }
    let mut temp = [0u8; 4096];
    let len = do_format!(&mut temp, size.saturating_sub(1), fmt, args);
    let copy_len = len.min(size - 1);
    ptr::copy_nonoverlapping(temp.as_ptr(), out, copy_len);
    ptr::write(out.add(copy_len), 0);
    len as i32
}

fn int_to_str(mut v: i64, base: u64, buf: &mut [u8]) -> usize {
    if buf.is_empty() { return 0; }
    let neg = v < 0;
    if neg { v = -v; }
    uint_to_str_inner(v as u64, base, neg, buf)
}

fn uint_to_str(v: u64, base: u64, buf: &mut [u8]) -> usize { uint_to_str_inner(v, base, false, buf) }

fn uint_to_str_inner(mut v: u64, base: u64, neg: bool, buf: &mut [u8]) -> usize {
    let mut tmp = [0u8; 24];
    let mut i = 0;
    if v == 0 { tmp[i] = b'0'; i += 1; }
    while v > 0 { let d = (v % base) as u8; tmp[i] = if d < 10 { b'0' + d } else { b'a' + d - 10 }; i += 1; v /= base; }
    if neg { tmp[i] = b'-'; i += 1; }
    let len = i.min(buf.len());
    for j in 0..len { buf[j] = tmp[i - 1 - j]; }
    len
}
