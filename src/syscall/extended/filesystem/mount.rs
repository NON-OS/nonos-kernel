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
use super::helpers::read_user_string;

pub fn handle_chroot(path: u64) -> SyscallResult {
    if path == 0 {
        return errno(14);
    }

    let path_str = match read_user_string(path, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::process::set_root(&path_str) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: true, audit_required: true },
        Err(_) => errno(2),
    }
}

pub fn handle_mount(source: u64, target: u64, filesystemtype: u64, mountflags: u64, _data: u64) -> SyscallResult {
    if target == 0 {
        return errno(14);
    }

    let source_str = if source != 0 {
        match read_user_string(source, 4096) {
            Ok(s) => Some(s),
            Err(_) => return errno(14),
        }
    } else {
        None
    };

    let target_str = match read_user_string(target, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let fstype = if filesystemtype != 0 {
        match read_user_string(filesystemtype, 256) {
            Ok(s) => Some(s),
            Err(_) => return errno(14),
        }
    } else {
        None
    };

    let _ = mountflags;

    match crate::fs::mount(source_str.as_deref(), &target_str, fstype.as_deref()) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: true, audit_required: true },
        Err(_) => errno(22),
    }
}

pub fn handle_umount2(target: u64, _flags: i32) -> SyscallResult {
    if target == 0 {
        return errno(14);
    }

    let target_str = match read_user_string(target, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    match crate::fs::umount(&target_str) {
        Ok(()) => SyscallResult { value: 0, capability_consumed: true, audit_required: true },
        Err(_) => errno(22),
    }
}
