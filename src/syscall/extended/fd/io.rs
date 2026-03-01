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

pub fn handle_sendfile(out_fd: i32, in_fd: i32, offset: u64, count: u64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(in_fd) || !crate::fs::fd::fd_is_valid(out_fd) {
        return errno(9);
    }

    if count == 0 {
        return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
    }

    let transfer_size = count.min(64 * 1024) as usize;

    let read_offset = if offset != 0 {
        let off = unsafe { core::ptr::read(offset as *const i64) };
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
        let new_offset = (read_offset.unwrap_or(0) + bytes_written as u64) as i64;
        unsafe { core::ptr::write(offset as *mut i64, new_offset) };
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

    match crate::fs::fd::fd_read_at(fd, buf as *mut u8, read_size, offset as usize) {
        Ok(n) => SyscallResult { value: n as i64, capability_consumed: false, audit_required: false },
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

    match crate::fs::fd::fd_write_at(fd, buf as *const u8, write_size, offset as usize) {
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
        let iov_ptr = iov + (i as u64 * 16);
        let base = unsafe { core::ptr::read(iov_ptr as *const u64) };
        let len = unsafe { core::ptr::read((iov_ptr + 8) as *const u64) };

        if base == 0 || len == 0 {
            continue;
        }

        match crate::fs::fd::fd_read(fd, base as *mut u8, len as usize) {
            Ok(n) => total += n as i64,
            Err(_) => break,
        }
    }

    SyscallResult { value: total, capability_consumed: false, audit_required: false }
}

pub fn handle_writev(fd: i32, iov: u64, iovcnt: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if iov == 0 || iovcnt <= 0 {
        return errno(22);
    }

    let mut total = 0i64;

    for i in 0..iovcnt {
        let iov_ptr = iov + (i as u64 * 16);
        let base = unsafe { core::ptr::read(iov_ptr as *const u64) };
        let len = unsafe { core::ptr::read((iov_ptr + 8) as *const u64) };

        if base == 0 || len == 0 {
            continue;
        }

        match crate::fs::fd::fd_write(fd, base as *const u8, len as usize) {
            Ok(n) => total += n as i64,
            Err(_) => break,
        }
    }

    SyscallResult { value: total, capability_consumed: false, audit_required: false }
}
