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

pub const FD_CLOEXEC: u32 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FdType {
    File,
    Socket,
    Pipe,
    EventFd,
    TimerFd,
    SignalFd,
    Epoll,
    Directory,
    Unknown,
}

#[derive(Clone, Debug)]
pub struct FdEntry {
    pub fd: i32,
    pub fd_type: FdType,
    pub internal_id: usize,
    pub is_read_end: bool,
    pub is_write_end: bool,
    pub flags: u32,
    pub status_flags: u32,
}

impl FdEntry {
    pub fn new(fd_type: FdType, internal_id: usize) -> Self {
        Self {
            fd: -1,
            fd_type,
            internal_id,
            is_read_end: false,
            is_write_end: false,
            flags: 0,
            status_flags: 0,
        }
    }

    pub fn with_pipe(pipe_id: usize, is_read: bool) -> Self {
        Self {
            fd: -1,
            fd_type: FdType::Pipe,
            internal_id: pipe_id,
            is_read_end: is_read,
            is_write_end: !is_read,
            flags: 0,
            status_flags: 0,
        }
    }

    pub fn is_cloexec(&self) -> bool {
        (self.flags & FD_CLOEXEC) != 0
    }
}

pub struct FdTableStats {
    pub total_fds: usize,
    pub file_count: usize,
    pub socket_count: usize,
    pub pipe_count: usize,
    pub eventfd_count: usize,
    pub timerfd_count: usize,
    pub signalfd_count: usize,
    pub epoll_count: usize,
}
