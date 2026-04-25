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
use super::helpers::PROCESS_CWD;
use crate::syscall::SyscallResult;
use crate::usercopy::copy_to_user;
use alloc::string::String;
use alloc::vec::Vec;

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

    let dirent_buf = build_dirent_buffer(&entries, count as usize);
    let buf_len = dirent_buf.len();

    if buf_len > 0 {
        if copy_to_user(dirp, &dirent_buf).is_err() {
            return errno(14);
        }
    }

    SyscallResult { value: buf_len as i64, capability_consumed: false, audit_required: false }
}

fn build_dirent_buffer(entries: &[String], max_size: usize) -> Vec<u8> {
    let mut buf = Vec::new();
    let mut entry_offset: i64 = 0;

    for entry in entries {
        let name_bytes = entry.as_bytes();
        if name_bytes.len() > 255 {
            continue;
        }
        let reclen = match 20usize.checked_add(name_bytes.len()) {
            Some(v) => v,
            None => continue,
        };
        let reclen_aligned = (reclen + 7) & !7;

        if buf.len().saturating_add(reclen_aligned) > max_size {
            break;
        }

        entry_offset += 1;

        buf.extend_from_slice(&(entry_offset as u64).to_ne_bytes());
        buf.extend_from_slice(&entry_offset.to_ne_bytes());
        buf.extend_from_slice(&(reclen_aligned as u16).to_ne_bytes());
        buf.push(8);
        buf.extend_from_slice(name_bytes);
        buf.push(0);

        while buf.len() % 8 != 0 {
            buf.push(0);
        }
    }

    buf
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
