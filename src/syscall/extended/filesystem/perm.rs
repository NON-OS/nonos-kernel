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

pub fn handle_chmod(pathname: u64, mode: u32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::fs::chmod(&path, mode) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(2),
    }
}

pub fn handle_fchmod(fd: i32, mode: u32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    match crate::fs::fd::fd_chmod(fd, mode) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(1),
    }
}

pub fn handle_fchmodat(dirfd: i32, pathname: u64, mode: u32, _flags: i32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);

    match crate::fs::chmod(&full_path, mode) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(2),
    }
}

pub fn handle_chown(pathname: u64, owner: u32, group: u32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::fs::chown(&path, owner, group) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(2),
    }
}

pub fn handle_fchown(fd: i32, owner: u32, group: u32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    match crate::fs::fd::fd_chown(fd, owner, group) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(1),
    }
}

pub fn handle_lchown(pathname: u64, owner: u32, group: u32) -> SyscallResult {
    handle_chown(pathname, owner, group)
}

pub fn handle_fchownat(dirfd: i32, pathname: u64, owner: u32, group: u32, _flags: i32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);

    match crate::fs::chown(&full_path, owner, group) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(2),
    }
}

pub fn handle_umask(mask: u32) -> SyscallResult {
    let old_mask = crate::process::set_umask(mask);
    SyscallResult { value: old_mask as i64, capability_consumed: false, audit_required: false }
}
