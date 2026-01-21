// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

pub const PIPE_READ_FLAG: u32 = 0x40000000;
pub const PIPE_WRITE_FLAG: u32 = 0x20000000;
pub const PIPE_FLAG_MASK: u32 = 0x60000000;

#[inline]
pub fn is_pipe_read_fd(fd: u64) -> bool {
    (fd as u32 & PIPE_READ_FLAG) != 0
}

#[inline]
pub fn is_pipe_write_fd(fd: u64) -> bool {
    (fd as u32 & PIPE_WRITE_FLAG) != 0
}

#[inline]
pub fn pipe_fd_to_channel_id(fd: u64) -> u32 {
    (fd as u32) & !PIPE_FLAG_MASK
}

pub fn scancode_to_ascii(scancode: u8) -> Option<u8> {
    match scancode {
        0x1E => Some(b'a'),
        0x30 => Some(b'b'),
        0x2E => Some(b'c'),
        0x20 => Some(b'd'),
        0x12 => Some(b'e'),
        0x21 => Some(b'f'),
        0x22 => Some(b'g'),
        0x23 => Some(b'h'),
        0x17 => Some(b'i'),
        0x24 => Some(b'j'),
        0x25 => Some(b'k'),
        0x26 => Some(b'l'),
        0x32 => Some(b'm'),
        0x31 => Some(b'n'),
        0x18 => Some(b'o'),
        0x19 => Some(b'p'),
        0x10 => Some(b'q'),
        0x13 => Some(b'r'),
        0x1F => Some(b's'),
        0x14 => Some(b't'),
        0x16 => Some(b'u'),
        0x2F => Some(b'v'),
        0x11 => Some(b'w'),
        0x2D => Some(b'x'),
        0x15 => Some(b'y'),
        0x2C => Some(b'z'),
        0x02 => Some(b'1'),
        0x03 => Some(b'2'),
        0x04 => Some(b'3'),
        0x05 => Some(b'4'),
        0x06 => Some(b'5'),
        0x07 => Some(b'6'),
        0x08 => Some(b'7'),
        0x09 => Some(b'8'),
        0x0A => Some(b'9'),
        0x0B => Some(b'0'),
        0x39 => Some(b' '),
        0x1C => Some(b'\n'),
        0x0E => Some(0x08),
        _ => None,
    }
}

pub fn convert_open_flags(flags: u32) -> crate::fs::vfs::OpenFlags {
    crate::fs::vfs::OpenFlags::from_bits(flags)
}

pub fn read_user_string(ptr: u64) -> Result<String, i64> {
    if ptr == 0 {
        return Err(-14);
    }

    const MAX_PATH: usize = 4096;
    let mut buf = Vec::with_capacity(MAX_PATH);
    let str_ptr = ptr as *const u8;

    unsafe {
        for i in 0..MAX_PATH {
            let byte = *str_ptr.add(i);
            if byte == 0 {
                break;
            }
            buf.push(byte);
        }
    }

    String::from_utf8(buf).map_err(|_| -22)
}

pub fn read_user_string_array(ptr: u64) -> Result<Vec<String>, i64> {
    if ptr == 0 {
        return Ok(Vec::new());
    }

    let mut result = Vec::new();
    let arr_ptr = ptr as *const u64;

    unsafe {
        let mut i = 0;
        loop {
            let str_ptr = *arr_ptr.add(i);
            if str_ptr == 0 {
                break;
            }
            match read_user_string(str_ptr) {
                Ok(s) => result.push(s),
                Err(e) => return Err(e),
            }
            i += 1;
            if i > 1024 {
                break;
            }
        }
    }

    Ok(result)
}
