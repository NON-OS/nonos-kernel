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
use super::super::errno;
use super::helpers::{read_user_string, resolve_path_at};

pub fn handle_link(oldpath: u64, newpath: u64) -> SyscallResult {
    if oldpath == 0 || newpath == 0 {
        return errno(14);
    }

    let old_str = match read_user_string(oldpath, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let new_str = match read_user_string(newpath, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::fs::link(&old_str, &new_str) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(31),
    }
}

pub fn handle_linkat(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64, _flags: i32) -> SyscallResult {
    if oldpath == 0 || newpath == 0 {
        return errno(14);
    }

    let old_str = match read_user_string(oldpath, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let new_str = match read_user_string(newpath, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let old_full = resolve_path_at(olddirfd, &old_str);
    let new_full = resolve_path_at(newdirfd, &new_str);

    match crate::fs::link(&old_full, &new_full) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(31),
    }
}

pub fn handle_symlink(target: u64, linkpath: u64) -> SyscallResult {
    if target == 0 || linkpath == 0 {
        return errno(14);
    }

    let target_str = match read_user_string(target, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let link_str = match read_user_string(linkpath, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::fs::symlink(&target_str, &link_str) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(17),
    }
}

pub fn handle_symlinkat(target: u64, newdirfd: i32, linkpath: u64) -> SyscallResult {
    if target == 0 || linkpath == 0 {
        return errno(14);
    }

    let target_str = match read_user_string(target, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let link_str = match read_user_string(linkpath, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let link_full = resolve_path_at(newdirfd, &link_str);

    match crate::fs::symlink(&target_str, &link_full) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(17),
    }
}

pub fn handle_readlinkat(dirfd: i32, pathname: u64, buf: u64, bufsiz: u64) -> SyscallResult {
    if pathname == 0 || buf == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);

    match crate::fs::readlink(&full_path) {
        Ok(target) => {
            let bytes = target.as_bytes();
            let copy_len = bytes.len().min(bufsiz as usize);
            // SAFETY: buf is user-provided pointer for readlink output.
            unsafe {
                core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, copy_len);
            }
            SyscallResult { value: copy_len as i64, capability_consumed: false, audit_required: false }
        }
        Err(_) => errno(22),
    }
}
