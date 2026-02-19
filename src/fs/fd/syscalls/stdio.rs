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

use alloc::format;

use crate::fs::fd::error::{FdError, FdResult};

pub(crate) fn write_stdout(buf: *const u8, count: usize) -> FdResult<usize> {
    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    // ## SAFETY: Caller guarantees buf is valid for count bytes
    unsafe {
        let slice = core::slice::from_raw_parts(buf, count);
        for &byte in slice {
            if byte == b'\n' {
                crate::arch::x86_64::vga::print("\n");
            } else if byte.is_ascii_graphic() || byte == b' ' {
                let ch = byte as char;
                crate::arch::x86_64::vga::print(&format!("{}", ch));
            }
        }
    }
    Ok(count)
}

pub(crate) fn write_stderr(buf: *const u8, count: usize) -> FdResult<usize> {
    if buf.is_null() {
        return Err(FdError::NullPointer);
    }
    // ## SAFETY: Caller guarantees buf is valid for count bytes
    unsafe {
        let slice = core::slice::from_raw_parts(buf, count);
        for &byte in slice {
            let _ = crate::arch::x86_64::serial::write_byte(byte);
        }
    }
    Ok(count)
}

pub(crate) fn read_stdin(buf: *mut u8, count: usize) -> FdResult<usize> {
    if buf.is_null() {
        return Err(FdError::NullPointer);
    }
    if count == 0 {
        return Ok(0);
    }

    if let Some(ch) = crate::drivers::keyboard_buffer::read_char() {
        // ## SAFETY: buf is valid and non-null checked above
        unsafe { core::ptr::write(buf, ch as u8) }
        Ok(1)
    } else {
        Ok(0)
    }
}
