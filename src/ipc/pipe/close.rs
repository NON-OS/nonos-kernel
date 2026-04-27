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

use super::registry::{FD_TO_PIPE, PIPES};
use super::types::EBADF;

pub fn pipe_close(fd: i32) -> Result<(), i32> {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().remove(&fd) {
        Some(info) => info,
        None => return Err(EBADF),
    };
    let mut pipes = PIPES.lock();
    if let Some(pipe) = pipes.get_mut(&pipe_id) {
        if is_read_end {
            pipe.read_closed = true;
        } else {
            pipe.write_closed = true;
        }
        if pipe.read_closed && pipe.write_closed {
            pipes.remove(&pipe_id);
        }
    }
    Ok(())
}

pub fn pipe_set_nonblock(fd: i32, nonblock: bool) -> Result<(), i32> {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return Err(EBADF),
    };
    let mut pipes = PIPES.lock();
    if let Some(pipe) = pipes.get_mut(&pipe_id) {
        if is_read_end {
            pipe.read_nonblock = nonblock;
        } else {
            pipe.write_nonblock = nonblock;
        }
        Ok(())
    } else {
        Err(EBADF)
    }
}
