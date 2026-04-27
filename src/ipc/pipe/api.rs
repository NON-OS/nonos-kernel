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

use super::registry::{allocate_fd, FD_TO_PIPE, NEXT_PIPE_ID, PIPES};
use super::types::{Pipe, EAGAIN, EBADF, EPIPE, MAX_PIPES, PIPE_BUF_SIZE};
use core::sync::atomic::Ordering;

pub fn create_pipe() -> Result<(i32, i32), i32> {
    create_pipe_with_size(PIPE_BUF_SIZE)
}

pub fn create_pipe_with_size(size: usize) -> Result<(i32, i32), i32> {
    let pipes = PIPES.lock();
    if pipes.len() >= MAX_PIPES {
        drop(pipes);
        return Err(24);
    }
    drop(pipes);
    let pipe_id = NEXT_PIPE_ID.fetch_add(1, Ordering::SeqCst);
    let pipe = Pipe::new(pipe_id, size);
    PIPES.lock().insert(pipe_id, pipe);
    let read_fd = allocate_fd();
    let write_fd = allocate_fd();
    let mut fd_map = FD_TO_PIPE.lock();
    fd_map.insert(read_fd, (pipe_id, true));
    fd_map.insert(write_fd, (pipe_id, false));
    Ok((read_fd, write_fd))
}

pub fn pipe_read(fd: i32, buf: &mut [u8]) -> Result<usize, i32> {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return Err(EBADF),
    };
    if !is_read_end {
        return Err(EBADF);
    }
    let mut pipes = PIPES.lock();
    match pipes.get_mut(&pipe_id) {
        Some(pipe) => read_from_pipe(pipe, buf),
        None => Err(EBADF),
    }
}

fn read_from_pipe(pipe: &mut Pipe, buf: &mut [u8]) -> Result<usize, i32> {
    if pipe.bytes_available == 0 {
        if pipe.write_closed {
            return Ok(0);
        }
        return Err(EAGAIN);
    }
    let to_read = buf.len().min(pipe.bytes_available);
    for i in 0..to_read {
        buf[i] = pipe.buffer[pipe.read_pos];
        pipe.read_pos = (pipe.read_pos + 1) % pipe.capacity;
    }
    pipe.bytes_available -= to_read;
    Ok(to_read)
}

pub fn pipe_write(fd: i32, buf: &[u8]) -> Result<usize, i32> {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return Err(EBADF),
    };
    if is_read_end {
        return Err(EBADF);
    }
    let mut pipes = PIPES.lock();
    match pipes.get_mut(&pipe_id) {
        Some(pipe) => write_to_pipe(pipe, buf),
        None => Err(EBADF),
    }
}

fn write_to_pipe(pipe: &mut Pipe, buf: &[u8]) -> Result<usize, i32> {
    if pipe.read_closed {
        return Err(EPIPE);
    }
    if pipe.space_available() == 0 {
        return Err(EAGAIN);
    }
    let to_write = buf.len().min(pipe.space_available());
    for i in 0..to_write {
        pipe.buffer[pipe.write_pos] = buf[i];
        pipe.write_pos = (pipe.write_pos + 1) % pipe.capacity;
    }
    pipe.bytes_available += to_write;
    Ok(to_write)
}
