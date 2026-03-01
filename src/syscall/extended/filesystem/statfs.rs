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

pub fn handle_faccessat(dirfd: i32, pathname: u64, mode: i32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);
    let _ = mode;

    if let Some(vfs) = crate::fs::nonos_vfs::get_vfs() {
        if vfs.exists(&full_path) {
            return SyscallResult { value: 0, capability_consumed: false, audit_required: false };
        }
    }

    errno(2)
}

pub fn handle_statfs(path: u64, buf: u64) -> SyscallResult {
    if path == 0 || buf == 0 {
        return errno(14);
    }

    let path_str = match read_user_string(path, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    if !crate::fs::nonos_vfs::get_vfs().map(|v| v.exists(&path_str)).unwrap_or(false) {
        return errno(2);
    }

    // SAFETY: buf is user-provided pointer for statfs output.
    unsafe {
        let ptr = buf as *mut u8;
        core::ptr::write_bytes(ptr, 0, 120);
        core::ptr::write((ptr.add(0)) as *mut u64, 0x4e4f4e4f53);
        core::ptr::write((ptr.add(8)) as *mut u64, 4096);
        core::ptr::write((ptr.add(16)) as *mut u64, 1024 * 1024);
        core::ptr::write((ptr.add(24)) as *mut u64, 512 * 1024);
        core::ptr::write((ptr.add(32)) as *mut u64, 512 * 1024);
        core::ptr::write((ptr.add(40)) as *mut u64, 1000000);
        core::ptr::write((ptr.add(48)) as *mut u64, 999000);
        core::ptr::write((ptr.add(88)) as *mut u64, 255);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_fstatfs(fd: i32, buf: u64) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    if buf == 0 {
        return errno(14);
    }

    // SAFETY: buf is user-provided pointer for statfs output.
    unsafe {
        let ptr = buf as *mut u8;
        core::ptr::write_bytes(ptr, 0, 120);
        core::ptr::write((ptr.add(0)) as *mut u64, 0x4e4f4e4f53);
        core::ptr::write((ptr.add(8)) as *mut u64, 4096);
        core::ptr::write((ptr.add(16)) as *mut u64, 1024 * 1024);
        core::ptr::write((ptr.add(24)) as *mut u64, 512 * 1024);
        core::ptr::write((ptr.add(32)) as *mut u64, 512 * 1024);
        core::ptr::write((ptr.add(40)) as *mut u64, 1000000);
        core::ptr::write((ptr.add(48)) as *mut u64, 999000);
        core::ptr::write((ptr.add(88)) as *mut u64, 255);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}

pub fn handle_statx(dirfd: i32, pathname: u64, flags: i32, mask: u32, statxbuf: u64) -> SyscallResult {
    if statxbuf == 0 {
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

    let _ = mask;

    // SAFETY: statxbuf is user-provided pointer for statx output.
    unsafe {
        let buf = statxbuf as *mut u8;
        core::ptr::write_bytes(buf, 0, 256);
        core::ptr::write((buf.add(0)) as *mut u32, 0x7FF);
        core::ptr::write((buf.add(4)) as *mut u32, 4096);
        core::ptr::write((buf.add(8)) as *mut u64, 0);
        core::ptr::write((buf.add(16)) as *mut u32, 1);
        core::ptr::write((buf.add(20)) as *mut u32, 0);
        core::ptr::write((buf.add(24)) as *mut u32, 0);
        core::ptr::write((buf.add(28)) as *mut u16, (metadata.mode & 0xFFFF) as u16);
        core::ptr::write((buf.add(32)) as *mut u64, metadata.inode);
        core::ptr::write((buf.add(40)) as *mut u64, metadata.size);
        core::ptr::write((buf.add(48)) as *mut u64, (metadata.size + 511) / 512);
    }

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
