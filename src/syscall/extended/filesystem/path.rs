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
use super::helpers::{PROCESS_CWD, read_user_string, normalize_path};

pub fn handle_getcwd(buf: u64, size: u64) -> SyscallResult {
    if buf == 0 || size == 0 {
        return errno(22);
    }

    let pid = crate::process::current_pid().unwrap_or(0);

    let cwd = {
        let cwd_map = PROCESS_CWD.read();
        cwd_map.get(&pid).cloned().unwrap_or_else(|| String::from("/"))
    };

    if cwd.len() + 1 > size as usize {
        return errno(34);
    }

    let bytes = cwd.as_bytes();
    // SAFETY: buf is user-provided pointer for cwd output.
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), buf as *mut u8, bytes.len());
        core::ptr::write((buf + bytes.len() as u64) as *mut u8, 0);
    }

    SyscallResult { value: buf as i64, capability_consumed: false, audit_required: false }
}

pub fn handle_chdir(path: u64) -> SyscallResult {
    if path == 0 {
        return errno(14);
    }

    let path_str = match read_user_string(path, 4096) {
        Ok(s) => s,
        Err(_) => return errno(14),
    };

    let normalized = normalize_path(&path_str);

    let pid = crate::process::current_pid().unwrap_or(0);
    PROCESS_CWD.write().insert(pid, normalized);

    SyscallResult { value: 0, capability_consumed: false, audit_required: false }
}
