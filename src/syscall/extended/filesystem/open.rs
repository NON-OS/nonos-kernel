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

use alloc::string::String;
use crate::syscall::SyscallResult;
use super::super::errno;
use super::helpers::{read_user_string, resolve_path_at};

pub fn handle_mknod(pathname: u64, mode: u32, dev: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::fs::mknod(&path, mode, dev) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(17),
    }
}

pub fn handle_mknodat(dirfd: i32, pathname: u64, mode: u32, dev: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);

    match crate::fs::mknod(&full_path, mode, dev) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(17),
    }
}

pub fn handle_openat(dirfd: i32, pathname: u64, flags: i32, mode: u32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);

    match crate::fs::fd::open_file_create(&full_path, flags, mode) {
        Some(fd) => SyscallResult { value: fd as i64, capability_consumed: false, audit_required: true },
        None => errno(2),
    }
}

pub fn handle_newfstatat(dirfd: i32, pathname: u64, statbuf: u64, flags: i32) -> SyscallResult {
    if statbuf == 0 {
        return errno(14);
    }

    let path = if pathname != 0 {
        match read_user_string(pathname, 4096) {
            Ok(s) => s,
            Err(_) => return errno(14),
        }
    } else {
        String::new()
    };

    let full_path = if path.is_empty() && (flags & 0x1000) != 0 {
        match crate::fs::fd::fd_get_path(dirfd) {
            Ok(p) => p,
            Err(_) => return errno(9),
        }
    } else {
        resolve_path_at(dirfd, &path)
    };

    let vfs = match crate::fs::nonos_vfs::get_vfs() {
        Some(v) => v,
        None => return errno(5),
    };

    let metadata = match vfs.stat(&full_path) {
        Ok(m) => m,
        Err(_) => return errno(2),
    };

    // SAFETY: statbuf is user-provided pointer for stat output.
    unsafe {
        let buf = statbuf as *mut u8;
        core::ptr::write_bytes(buf, 0, 128);
        core::ptr::write((buf.add(0)) as *mut u64, 1);
        core::ptr::write((buf.add(8)) as *mut u64, metadata.inode);
        core::ptr::write((buf.add(24)) as *mut u32, metadata.mode);
        core::ptr::write((buf.add(48)) as *mut i64, metadata.size as i64);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
