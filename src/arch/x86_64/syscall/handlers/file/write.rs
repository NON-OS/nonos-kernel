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

use crate::usercopy::{validate_user_read, copy_from_user};
use super::super::super::util::{is_pipe_read_fd, is_pipe_write_fd, pipe_fd_to_channel_id};
use super::write_stdout::{write_to_stdout, write_to_stderr};

const EFAULT: i64 = -14;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;
const EPERM: i64 = -1;

pub fn syscall_write(fd: u64, buf: u64, count: u64, _: u64, _: u64, _: u64) -> u64 {
    if buf == 0 {
        return EFAULT as u64;
    }
    if count == 0 {
        return 0;
    }
    if validate_user_read(buf, count as usize).is_err() {
        return EFAULT as u64;
    }
    let mut kernel_buf = alloc::vec![0u8; count as usize];
    if copy_from_user(buf, &mut kernel_buf).is_err() {
        return EFAULT as u64;
    }
    if is_pipe_write_fd(fd) {
        return write_to_pipe(fd, &kernel_buf);
    }
    if is_pipe_read_fd(fd) {
        return EBADF as u64;
    }
    write_to_descriptor(fd, &kernel_buf)
}

fn write_to_pipe(fd: u64, data: &[u8]) -> u64 {
    let channel_id = pipe_fd_to_channel_id(fd);
    match crate::ipc::send_message(channel_id, data) {
        Ok(()) => data.len() as u64,
        Err(crate::ipc::IpcError::BufferFull) => EAGAIN as u64,
        Err(crate::ipc::IpcError::PermissionDenied) => EPERM as u64,
        Err(_) => EBADF as u64,
    }
}

fn write_to_descriptor(fd: u64, data: &[u8]) -> u64 {
    match fd {
        0 => EBADF as u64,
        1 => write_to_stdout(data),
        2 => write_to_stderr(data),
        _ => write_to_file(fd, data),
    }
}

fn write_to_file(fd: u64, data: &[u8]) -> u64 {
    match crate::fs::nonos_vfs::vfs_write(fd as u32, data) {
        Ok(n) => n as u64,
        Err(_) => EBADF as u64,
    }
}
