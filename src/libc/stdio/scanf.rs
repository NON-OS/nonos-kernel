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

use super::file::FILE;
use core::ptr;

macro_rules! do_parse {
    ($input:expr, $fmt:expr, $args:expr) => {{
        let input = $input;
        let fmt = $fmt;
        let mut count = 0i32;
        let mut ipos = 0usize;
        let mut fpos = 0usize;
        unsafe {
            while ptr::read(fmt.add(fpos)) != 0 && ipos < input.len() {
                let c = ptr::read(fmt.add(fpos));
                if c == b'%' {
                    fpos += 1;
                    let spec = ptr::read(fmt.add(fpos));
                    match spec {
                        b'd' | b'i' => {
                            let (v, consumed) = parse_int(&input[ipos..]);
                            if consumed > 0 {
                                let p: *mut i32 = $args.arg();
                                if !p.is_null() {
                                    ptr::write(p, v as i32);
                                    ipos += consumed;
                                    count += 1;
                                }
                            }
                        }
                        b's' => {
                            let p: *mut u8 = $args.arg();
                            if !p.is_null() {
                                let mut j = 0;
                                while ipos < input.len() && !input[ipos].is_ascii_whitespace() {
                                    ptr::write(p.add(j), input[ipos]);
                                    ipos += 1;
                                    j += 1;
                                }
                                ptr::write(p.add(j), 0);
                                if j > 0 {
                                    count += 1;
                                }
                            }
                        }
                        b'c' => {
                            if ipos < input.len() {
                                let p: *mut u8 = $args.arg();
                                if !p.is_null() {
                                    ptr::write(p, input[ipos]);
                                    ipos += 1;
                                    count += 1;
                                }
                            }
                        }
                        _ => {}
                    }
                } else if c.is_ascii_whitespace() {
                    while ipos < input.len() && input[ipos].is_ascii_whitespace() {
                        ipos += 1;
                    }
                } else {
                    if ipos < input.len() && input[ipos] == c {
                        ipos += 1;
                    } else {
                        break;
                    }
                }
                fpos += 1;
            }
        }
        count
    }};
}

#[no_mangle]
pub unsafe extern "C" fn scanf(fmt: *const u8, mut args: ...) -> i32 {
    let mut buf = [0u8; 1024];
    let n = crate::libc::unistd::read(0, buf.as_mut_ptr(), buf.len());
    if n <= 0 {
        return -1;
    }
    do_parse!(&buf[..n as usize], fmt, args)
}

#[no_mangle]
pub unsafe extern "C" fn fscanf(stream: *mut FILE, fmt: *const u8, mut args: ...) -> i32 {
    if stream.is_null() || fmt.is_null() {
        return -1;
    }
    let mut buf = [0u8; 1024];
    let n = crate::libc::unistd::read((*stream).fd, buf.as_mut_ptr(), buf.len());
    if n <= 0 {
        return -1;
    }
    do_parse!(&buf[..n as usize], fmt, args)
}

#[no_mangle]
pub unsafe extern "C" fn sscanf(s: *const u8, fmt: *const u8, mut args: ...) -> i32 {
    if s.is_null() || fmt.is_null() {
        return -1;
    }
    let mut len = 0;
    while ptr::read(s.add(len)) != 0 && len < 4096 {
        len += 1;
    }
    let slice = core::slice::from_raw_parts(s, len);
    do_parse!(slice, fmt, args)
}

fn parse_int(s: &[u8]) -> (i64, usize) {
    let mut i = 0;
    while i < s.len() && s[i].is_ascii_whitespace() {
        i += 1;
    }
    let neg = i < s.len() && s[i] == b'-';
    if neg {
        i += 1;
    }
    let start = i;
    let mut v: i64 = 0;
    while i < s.len() && s[i].is_ascii_digit() {
        v = v.saturating_mul(10).saturating_add((s[i] - b'0') as i64);
        i += 1;
    }
    if i == start {
        return (0, 0);
    }
    (if neg { -v } else { v }, i)
}
