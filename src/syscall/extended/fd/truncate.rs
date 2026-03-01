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

pub fn handle_ftruncate(fd: i32, length: u64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if !crate::fs::fd::fd_is_writable(fd) {
        return errno(22);
    }

    match crate::fs::fd::fd_truncate(fd, length as usize) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(5),
    }
}

pub fn handle_creat(pathname: u64, mode: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match crate::syscall::extended::filesystem::read_user_string(pathname, 4096) {
        Ok(p) => p,
        Err(_) => return errno(14),
    };

    const O_CREAT: i32 = 0x40;
    const O_WRONLY: i32 = 0x01;
    const O_TRUNC: i32 = 0x200;
    let flags = O_CREAT | O_WRONLY | O_TRUNC;

    match crate::fs::fd::open_file_create(&path, flags, mode as u32) {
        Some(fd) => SyscallResult { value: fd as i64, capability_consumed: false, audit_required: true },
        None => errno(13),
    }
}

pub fn handle_truncate(path: u64, length: u64) -> SyscallResult {
    if path == 0 {
        return errno(14);
    }

    let path_str = match crate::syscall::extended::filesystem::read_user_string(path, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::fs::truncate(&path_str, length) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: false },
        Err(_) => errno(2),
    }
}
