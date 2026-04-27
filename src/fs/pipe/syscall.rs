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

use super::buffer::PipeBuffer;
use super::reader::PipeReader;
use super::writer::PipeWriter;
use crate::usercopy::copy_to_user;
use alloc::sync::Arc;
use spin::Mutex;

pub const O_CLOEXEC: u32 = 0x80000;
pub const O_NONBLOCK: u32 = 0x800;
pub const O_DIRECT: u32 = 0x4000;

pub fn sys_pipe(pipefd: u64) -> Result<i64, i32> {
    sys_pipe2(pipefd, 0)
}

pub fn sys_pipe2(pipefd: u64, flags: u32) -> Result<i64, i32> {
    if (flags & !(O_CLOEXEC | O_NONBLOCK | O_DIRECT)) != 0 {
        return Err(-22);
    }
    let buffer = Arc::new(Mutex::new(PipeBuffer::new()));
    let reader = PipeReader::new(buffer.clone(), flags);
    let writer = PipeWriter::new(buffer, flags);
    let read_fd = crate::fs::allocate_fd()?;
    let write_fd = crate::fs::allocate_fd()?;
    crate::fs::register_pipe_reader(read_fd, reader);
    crate::fs::register_pipe_writer(write_fd, writer);
    if (flags & O_CLOEXEC) != 0 {
        crate::fs::set_cloexec(read_fd, true);
        crate::fs::set_cloexec(write_fd, true);
    }
    let fds = [read_fd, write_fd];
    let fds_bytes: [u8; 8] = unsafe { core::mem::transmute::<[i32; 2], [u8; 8]>(fds) };
    copy_to_user(pipefd, &fds_bytes)?;
    Ok(0)
}

pub fn is_pipe(fd: i32) -> bool {
    crate::fs::is_pipe_fd(fd)
}

pub fn get_pipe_size(fd: i32) -> Result<usize, i32> {
    crate::fs::get_pipe_buffer_size(fd)
}

pub fn set_pipe_size(fd: i32, size: usize) -> Result<usize, i32> {
    crate::fs::set_pipe_buffer_size(fd, size)
}
