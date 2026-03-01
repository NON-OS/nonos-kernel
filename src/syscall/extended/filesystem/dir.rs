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
use super::helpers::PROCESS_CWD;

pub fn handle_getdents64(_fd: u64, dirp: u64, count: u64) -> SyscallResult {
    if dirp == 0 || count == 0 {
        return errno(22);
    }

    let pid = crate::process::current_pid().unwrap_or(0);
    let cwd = {
        let cwd_map = PROCESS_CWD.read();
        cwd_map.get(&pid).cloned().unwrap_or_else(|| String::from("/"))
    };

    let entries = match crate::fs::nonos_filesystem::list_dir(&cwd) {
        Ok(e) => e,
        Err(_) => return errno(2),
    };

    let mut offset = 0u64;
    let mut entry_offset = 0i64;

    for entry in entries {
        let name_bytes = entry.as_bytes();
        let reclen = 19 + name_bytes.len() + 1;
        let reclen_aligned = (reclen + 7) & !7;

        if offset + reclen_aligned as u64 > count {
            break;
        }

        entry_offset += 1;

        // SAFETY: dirp is user-provided pointer for directory entries output.
        unsafe {
            let ptr = dirp + offset;
            core::ptr::write(ptr as *mut u64, entry_offset as u64);
            core::ptr::write((ptr + 8) as *mut i64, entry_offset);
            core::ptr::write((ptr + 16) as *mut u16, reclen_aligned as u16);
            core::ptr::write((ptr + 18) as *mut u8, 8);
            core::ptr::copy_nonoverlapping(
                name_bytes.as_ptr(),
                (ptr + 19) as *mut u8,
                name_bytes.len(),
            );
            core::ptr::write((ptr + 19 + name_bytes.len() as u64) as *mut u8, 0);
        }

        offset += reclen_aligned as u64;
    }

    SyscallResult { value: offset as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_getdents(fd: i32, dirp: u64, count: u64) -> SyscallResult {
    handle_getdents64(fd as u64, dirp, count)
}

pub fn handle_fchdir(fd: i32) -> SyscallResult {
    if !crate::fs::fd::fd_is_valid(fd) {
        return errno(9);
    }

    let path = match crate::fs::fd::fd_get_path(fd) {
        Ok(p) => p,
        Err(_) => return errno(20),
    };

    let pid = crate::process::current_pid().unwrap_or(0);
    PROCESS_CWD.write().insert(pid, path);

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
