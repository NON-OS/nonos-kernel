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

use alloc::vec::Vec;

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;
use crate::usercopy::{read_user_value, write_user_value};

pub fn handle_sendfile(out_fd: i32, in_fd: i32, offset: u64, count: u64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(in_fd) || !crate::fs::fd::fd_is_valid(out_fd) {
        return errno(9);
    }

    if count == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let transfer_size = count.min(64 * 1024) as usize;

    let read_offset = if offset != 0 {
        let off: i64 = match read_user_value(offset) {
            Ok(v) => v,
            Err(_) => return errno(14),
        };
        Some(off as u64)
    } else {
        None
    };

    let mut buffer = Vec::with_capacity(transfer_size);
    buffer.resize(transfer_size, 0u8);

    let bytes_read = if let Some(off) = read_offset {
        crate::fs::fd::fd_read_at(in_fd, buffer.as_mut_ptr(), transfer_size, off as usize)
    } else {
        crate::fs::fd::fd_read(in_fd, buffer.as_mut_ptr(), transfer_size)
    };

    let bytes_read = match bytes_read {
        Ok(n) => n,
        Err(_) => return errno(5),
    };

    if bytes_read == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let bytes_written = match crate::fs::fd::fd_write(out_fd, buffer.as_ptr(), bytes_read) {
        Ok(n) => n,
        Err(_) => return errno(5),
    };

    if offset != 0 {
        if let Some(new_off) = read_offset.unwrap_or(0).checked_add(bytes_written as u64) {
            let _ = write_user_value(offset, &(new_off as i64));
        }
    }

    SyscallResult { value: bytes_written as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_pread64(fd: i32, buf: u64, count: u64, offset: i64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if buf == 0 {
        return errno(14);
    }

    if count == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let read_size = count.min(1024 * 1024) as usize;
    if crate::usercopy::validate_user_write(buf, read_size).is_err() { return errno(14); }

    let mut kernel_buf = Vec::with_capacity(read_size);
    kernel_buf.resize(read_size, 0u8);

    match crate::fs::fd::fd_read_at(fd, kernel_buf.as_mut_ptr(), read_size, offset as usize) {
        Ok(n) => {
            if crate::usercopy::copy_to_user(buf, &kernel_buf[..n]).is_err() { return errno(14); }
            SyscallResult { value: n as i64, capability_consumed: false, audit_required: false }
        }
        Err(_) => errno(5),
    }
}

pub fn handle_pwrite64(fd: i32, buf: u64, count: u64, offset: i64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if buf == 0 {
        return errno(14);
    }

    if count == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let write_size = count.min(1024 * 1024) as usize;
    if crate::usercopy::validate_user_read(buf, write_size).is_err() { return errno(14); }

    let mut kernel_buf = Vec::with_capacity(write_size);
    kernel_buf.resize(write_size, 0u8);
    if crate::usercopy::copy_from_user(buf, &mut kernel_buf).is_err() { return errno(14); }

    match crate::fs::fd::fd_write_at(fd, kernel_buf.as_ptr(), write_size, offset as usize) {
        Ok(n) => SyscallResult { value: n as i64, capability_consumed: false, audit_required: false },
        Err(_) => errno(5),
    }
}

pub fn handle_readv(fd: i32, iov: u64, iovcnt: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if iov == 0 || iovcnt <= 0 {
        return errno(22);
    }

    let mut total = 0i64;

    for i in 0..iovcnt {
        let iov_offset = match (i as u64).checked_mul(16) {
            Some(v) => v,
            None => break,
        };
        let iov_ptr = match iov.checked_add(iov_offset) {
            Some(v) => v,
            None => break,
        };
        let base: u64 = match read_user_value(iov_ptr) {
            Ok(v) => v,
            Err(_) => break,
        };
        let len_ptr = match iov_ptr.checked_add(8) {
            Some(v) => v,
            None => break,
        };
        let len: u64 = match read_user_value(len_ptr) {
            Ok(v) => v,
            Err(_) => break,
        };
        if base == 0 || len == 0 { continue; }
        let len = len.min(1024 * 1024) as usize;
        if crate::usercopy::validate_user_write(base, len).is_err() { break; }
        let mut kernel_buf = Vec::with_capacity(len);
        kernel_buf.resize(len, 0u8);
        match crate::fs::fd::fd_read(fd, kernel_buf.as_mut_ptr(), len) {
            Ok(n) => {
                if crate::usercopy::copy_to_user(base, &kernel_buf[..n]).is_err() { break; }
                total = total.saturating_add(n as i64);
            }
            Err(_) => break,
        }
    }
    SyscallResult { value: total, capability_consumed: false, audit_required: false }
}

pub fn handle_writev(fd: i32, iov: u64, iovcnt: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) { return errno(9); }
    if iov == 0 || iovcnt <= 0 { return errno(22); }
    let mut total = 0i64;
    for i in 0..iovcnt {
        let iov_offset = match (i as u64).checked_mul(16) {
            Some(v) => v,
            None => break,
        };
        let iov_ptr = match iov.checked_add(iov_offset) {
            Some(v) => v,
            None => break,
        };
        let base: u64 = match read_user_value(iov_ptr) {
            Ok(v) => v,
            Err(_) => break,
        };
        let len_ptr = match iov_ptr.checked_add(8) {
            Some(v) => v,
            None => break,
        };
        let len: u64 = match read_user_value(len_ptr) {
            Ok(v) => v,
            Err(_) => break,
        };
        if base == 0 || len == 0 { continue; }
        let len = len.min(1024 * 1024) as usize;
        if crate::usercopy::validate_user_read(base, len).is_err() { break; }
        let mut kernel_buf = Vec::with_capacity(len);
        kernel_buf.resize(len, 0u8);
        if crate::usercopy::copy_from_user(base, &mut kernel_buf).is_err() { break; }
        match crate::fs::fd::fd_write(fd, kernel_buf.as_ptr(), len) {
            Ok(n) => total = total.saturating_add(n as i64),
            Err(_) => break,
        }
    }
    SyscallResult { value: total, capability_consumed: false, audit_required: false }
}

pub fn handle_copy_file_range(fd_in: i32, off_in: u64, fd_out: i32, off_out: u64, len: u64, flags: u32) -> SyscallResult {
    let _ = flags;

    if !crate::fs::fd::fd_is_valid(fd_in) || !crate::fs::fd::fd_is_valid(fd_out) {
        return errno(9);
    }

    if len == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let transfer_size = len.min(64 * 1024) as usize;

    let read_offset = if off_in != 0 {
        match read_user_value::<i64>(off_in) {
            Ok(v) => Some(v as u64),
            Err(_) => return errno(14),
        }
    } else {
        None
    };

    let write_offset = if off_out != 0 {
        match read_user_value::<i64>(off_out) {
            Ok(v) => Some(v as u64),
            Err(_) => return errno(14),
        }
    } else {
        None
    };

    let mut buffer = Vec::with_capacity(transfer_size);
    buffer.resize(transfer_size, 0u8);

    let bytes_read = if let Some(off) = read_offset {
        crate::fs::fd::fd_read_at(fd_in, buffer.as_mut_ptr(), transfer_size, off as usize)
    } else {
        crate::fs::fd::fd_read(fd_in, buffer.as_mut_ptr(), transfer_size)
    };

    let bytes_read = match bytes_read {
        Ok(n) => n,
        Err(_) => return errno(5),
    };

    if bytes_read == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let bytes_written = if let Some(off) = write_offset {
        match crate::fs::fd::fd_write_at(fd_out, buffer.as_ptr(), bytes_read, off as usize) {
            Ok(n) => n,
            Err(_) => return errno(5),
        }
    } else {
        match crate::fs::fd::fd_write(fd_out, buffer.as_ptr(), bytes_read) {
            Ok(n) => n,
            Err(_) => return errno(5),
        }
    };

    if off_in != 0 {
        if let Some(new_off) = read_offset.unwrap_or(0).checked_add(bytes_written as u64) {
            let _ = write_user_value(off_in, &(new_off as i64));
        }
    }

    if off_out != 0 {
        if let Some(new_off) = write_offset.unwrap_or(0).checked_add(bytes_written as u64) {
            let _ = write_user_value(off_out, &(new_off as i64));
        }
    }

    SyscallResult { value: bytes_written as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_readahead(fd: i32, offset: i64, count: u64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if offset < 0 {
        return errno(22);
    }

    let _ = count;
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_fadvise64(fd: i32, offset: i64, len: i64, advice: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    let _ = (offset, len, advice);
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
