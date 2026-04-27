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

use super::super::errno;
use super::helpers::{normalize_path, read_user_string, PROCESS_CWD};
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;
use alloc::string::String;

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
    let mut out_buf = alloc::vec![0u8; cwd.len() + 1];
    out_buf[..cwd.len()].copy_from_slice(cwd.as_bytes());
    out_buf[cwd.len()] = 0;
    if copy_to_user(buf, &out_buf).is_err() {
        return errno(14);
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
