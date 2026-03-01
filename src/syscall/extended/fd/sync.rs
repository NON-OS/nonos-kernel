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

use crate::syscall::SyscallResult;
use crate::syscall::extended::errno;

pub fn handle_flock(fd: i32, operation: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    let _ = operation;
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_fsync(fd: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    match crate::fs::fd::fd_sync(fd) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(5),
    }
}

pub fn handle_fdatasync(fd: i32) -> SyscallResult {
    handle_fsync(fd)
}

pub fn handle_sync() -> SyscallResult {
    let _ = crate::fs::sync_all();
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_syncfs(fd: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    let _ = crate::fs::sync_all();
    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_fallocate(fd: i32, mode: i32, offset: i64, len: i64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if offset < 0 || len <= 0 {
        return errno(22);
    }

    let _ = mode;

    match crate::fs::fd::fd_allocate(fd, offset as usize, len as usize) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(28),
    }
}
