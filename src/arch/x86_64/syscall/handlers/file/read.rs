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

use super::super::super::util::{is_pipe_read_fd, is_pipe_write_fd, pipe_fd_to_channel_id};
use super::read_stdin::read_stdin_to_buffer;
use crate::usercopy::{copy_to_user, validate_user_write};

const EFAULT: i64 = -14;
const EBADF: i64 = -9;
const EAGAIN: i64 = -11;

pub fn syscall_read(fd: u64, buf: u64, count: u64, _: u64, _: u64, _: u64) -> u64 {
    if buf == 0 || count == 0 {
        return EFAULT as u64;
    }
    if validate_user_write(buf, count as usize).is_err() {
        return EFAULT as u64;
    }
    if is_pipe_read_fd(fd) {
        return read_from_pipe(fd, buf, count);
    }
    if is_pipe_write_fd(fd) {
        return EBADF as u64;
    }
    read_from_descriptor(fd, buf, count)
}

fn read_from_pipe(fd: u64, buf: u64, count: u64) -> u64 {
    let channel_id = pipe_fd_to_channel_id(fd);
    let mut kernel_buf = alloc::vec![0u8; count as usize];
    match crate::ipc::recv_message(channel_id, &mut kernel_buf) {
        Ok(n) => copy_result_to_user(buf, &kernel_buf, n),
        Err(crate::ipc::IpcError::WouldBlock) => EAGAIN as u64,
        Err(_) => EBADF as u64,
    }
}

fn read_from_descriptor(fd: u64, buf: u64, count: u64) -> u64 {
    let mut kernel_buf = alloc::vec![0u8; count as usize];
    let result: Result<usize, ()> = match fd {
        0 => read_stdin_to_buffer(&mut kernel_buf),
        1 | 2 => return EBADF as u64,
        _ => crate::fs::nonos_vfs::vfs_read(fd as u32, &mut kernel_buf).map_err(|_| ()),
    };
    match result {
        Ok(n) => copy_result_to_user(buf, &kernel_buf, n),
        Err(_) => EBADF as u64,
    }
}

fn copy_result_to_user(buf: u64, data: &[u8], len: usize) -> u64 {
    if copy_to_user(buf, &data[..len]).is_err() {
        EFAULT as u64
    } else {
        len as u64
    }
}
