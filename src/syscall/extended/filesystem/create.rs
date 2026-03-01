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

pub fn handle_mkdirat(dirfd: i32, pathname: u64, mode: u64) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);

    match crate::fs::mkdir(&full_path, mode as u32) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(17),
    }
}

pub fn handle_unlinkat(dirfd: i32, pathname: u64, flags: i32) -> SyscallResult {
    if pathname == 0 {
        return errno(14);
    }

    let path = match read_user_string(pathname, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let full_path = resolve_path_at(dirfd, &path);

    const AT_REMOVEDIR: i32 = 0x200;
    if (flags & AT_REMOVEDIR) != 0 {
        match crate::fs::rmdir(&full_path) {
            Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
            Err(_) => errno(2),
        }
    } else {
        match crate::fs::unlink(&full_path) {
            Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
            Err(_) => errno(2),
        }
    }
}

pub fn handle_renameat(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64) -> SyscallResult {
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

    match crate::fs::rename(&old_full, &new_full) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: false, audit_required: true },
        Err(_) => errno(2),
    }
}

pub fn handle_renameat2(olddirfd: i32, oldpath: u64, newdirfd: i32, newpath: u64, _flags: u32) -> SyscallResult {
    handle_renameat(olddirfd, oldpath, newdirfd, newpath)
}
