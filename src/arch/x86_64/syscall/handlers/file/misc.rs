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

use super::super::super::util::{PIPE_READ_FLAG, PIPE_WRITE_FLAG};

pub fn syscall_dup(fd: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    match crate::fs::fd::fd_dup(fd as i32) {
        Ok(new_fd) => new_fd as u64,
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_dup2(oldfd: u64, newfd: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    match crate::fs::fd::fd_dup2(oldfd as i32, newfd as i32) {
        Ok(fd) => fd as u64,
        Err(e) => e.to_errno() as u64,
    }
}

pub fn syscall_pipe(pipefd: u64, _: u64, _: u64, _: u64, _: u64, _: u64) -> u64 {
    if pipefd == 0 {
        return (-14i64) as u64;
    }

    match crate::ipc::create_channel(0) {
        Ok(channel_id) => {
            let fds = pipefd as *mut [i32; 2];
            unsafe {
                let read_fd = (channel_id | PIPE_READ_FLAG) as i32;
                let write_fd = (channel_id | PIPE_WRITE_FLAG) as i32;
                (*fds)[0] = read_fd;
                (*fds)[1] = write_fd;
            }
            0
        }
        Err(_) => (-24i64) as u64,
    }
}

pub fn syscall_ioctl(fd: u64, request: u64, arg: u64, _: u64, _: u64, _: u64) -> u64 {
    let result = crate::syscall::extended::misc::handle_ioctl(fd as i32, request, arg);
    result.value as u64
}
