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

use alloc::vec;
use crate::syscall::SyscallResult;
use crate::syscall::dispatch::util::errno;
use crate::usercopy::{read_user_value, write_user_value};

pub fn handle_splice(fd_in: i32, off_in: u64, fd_out: i32, off_out: u64, len: u64, _flags: u32) -> SyscallResult {
    if len == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }
    let in_offset: Option<i64> = if off_in != 0 {
        match read_user_value::<i64>(off_in) {
            Ok(v) => Some(v),
            Err(_) => return errno(14),
        }
    } else { None };
    let out_offset: Option<i64> = if off_out != 0 {
        match read_user_value::<i64>(off_out) {
            Ok(v) => Some(v),
            Err(_) => return errno(14),
        }
    } else { None };
    let read_len = len.min(65536) as usize;
    let buf = vec![0u8; read_len];
    let read_result = if let Some(off) = in_offset {
        crate::syscall::extended::handle_pread64(fd_in, buf.as_ptr() as u64, read_len as u64, off)
    } else {
        crate::syscall::dispatch::file_io::handle_read(fd_in, buf.as_ptr() as u64, read_len as u64)
    };
    if read_result.value < 0 {
        return read_result;
    }
    let bytes_read = read_result.value as usize;
    let write_result = if let Some(off) = out_offset {
        crate::syscall::extended::handle_pwrite64(fd_out, buf.as_ptr() as u64, bytes_read as u64, off)
    } else {
        crate::syscall::dispatch::file_io::handle_write(fd_out, buf.as_ptr() as u64, bytes_read as u64)
    };
    if write_result.value < 0 {
        return write_result;
    }
    if off_in != 0 {
        if let Some(off) = in_offset {
            let new_off = off + bytes_read as i64;
            let _ = write_user_value(off_in, &new_off);
        }
    }
    if off_out != 0 {
        if let Some(off) = out_offset {
            let new_off = off + write_result.value;
            let _ = write_user_value(off_out, &new_off);
        }
    }
    SyscallResult { value: write_result.value, capability_consumed: false, audit_required: false }
}
