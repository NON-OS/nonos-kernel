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

use super::super::super::util::{is_pipe_read_fd, is_pipe_write_fd, pipe_fd_to_channel_id, convert_open_flags};

pub fn syscall_open(pathname: u64, flags: u64, _mode: u64, _: u64, _: u64, _: u64) -> u64 {
    if pathname == 0 {
        return (-14i64) as u64;
    }

    let path_ptr = pathname as *const u8;
    let mut path_len = 0usize;
    const MAX_PATH: usize = 4096;

    unsafe {
        while path_len < MAX_PATH && *path_ptr.add(path_len) != 0 {
            path_len += 1;
        }
    }

    if path_len == 0 || path_len >= MAX_PATH {
        return (-36i64) as u64;
    }

    let path_slice = unsafe { core::slice::from_raw_parts(path_ptr, path_len) };
    let path_str = match core::str::from_utf8(path_slice) {
        Ok(s) => s,
        Err(_) => return (-22i64) as u64,
    };

    let vfs_flags = convert_open_flags(flags as u32);

    match crate::fs::nonos_vfs::vfs_open(path_str, vfs_flags) {
        Ok(fd) => fd as u64,
        Err(_) => (-2i64) as u64,
    }
}

pub fn syscall_close(fd: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if fd < 3 {
        return (-9i64) as u64;
    }

    if is_pipe_read_fd(fd) || is_pipe_write_fd(fd) {
        let channel_id = pipe_fd_to_channel_id(fd);
        match crate::ipc::destroy_channel(channel_id) {
            Ok(()) => 0,
            Err(_) => (-9i64) as u64,
        }
    } else {
        match crate::fs::nonos_vfs::vfs_close(fd as u32) {
            Ok(()) => 0,
            Err(_) => (-9i64) as u64,
        }
    }
}
