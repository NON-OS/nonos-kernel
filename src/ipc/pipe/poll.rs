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

pub struct PipeInfo {
    pub bytes_available: usize,
    pub space_available: usize,
    pub is_broken: bool,
}

pub fn get_pipe_info(pipe_id: usize) -> Option<PipeInfo> {
    let pipes = PIPES.lock();
    pipes.get(&(pipe_id as u32)).map(|pipe| PipeInfo {
        bytes_available: pipe.bytes_available,
        space_available: pipe.space_available(),
        is_broken: pipe.is_broken(),
    })
}

pub fn pipe_is_readable(fd: i32) -> bool {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return false,
    };
    if !is_read_end {
        return false;
    }
    let pipes = PIPES.lock();
    pipes.get(&pipe_id).map(|p| p.bytes_available > 0 || p.write_closed).unwrap_or(false)
}

pub fn pipe_is_writable(fd: i32) -> bool {
    let (pipe_id, is_read_end) = match FD_TO_PIPE.lock().get(&fd) {
        Some(&info) => info,
        None => return false,
    };
    if is_read_end {
        return false;
    }
    let pipes = PIPES.lock();
    pipes.get(&pipe_id).map(|p| p.space_available() > 0 && !p.read_closed).unwrap_or(false)
}

pub fn fd_to_pipe_id(fd: i32) -> Option<(u32, bool)> {
    FD_TO_PIPE.lock().get(&fd).copied()
}

pub fn is_pipe(fd: i32) -> bool {
    FD_TO_PIPE.lock().contains_key(&fd)
}

pub fn get_pipe_internal_id(pipe_id: u32) -> Option<u32> {
    let pipes = PIPES.lock();
    pipes.get(&pipe_id).map(|p| p.pipe_id())
}
