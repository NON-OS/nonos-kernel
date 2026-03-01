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

use crate::syscall::extended::epoll::{EPOLLIN, EPOLLOUT, EPOLLERR, EPOLLHUP, EPOLLPRI};

pub fn is_fd_valid(fd: i32) -> bool {
    use crate::process::fd_table;
    fd_table::get_fd(fd as u32).is_some()
}

pub fn is_fd_readable(fd: i32) -> bool {
    use crate::process::fd_table;

    let _entry = match fd_table::get_fd(fd as u32) {
        Some(e) => e,
        None => return false,
    };

    let events = crate::syscall::extended::epoll::check_fd_events_external(fd, EPOLLIN);
    (events & EPOLLIN) != 0
}

pub fn is_fd_writable(fd: i32) -> bool {
    let events = crate::syscall::extended::epoll::check_fd_events_external(fd, EPOLLOUT);
    (events & EPOLLOUT) != 0
}

pub fn has_fd_exception(fd: i32) -> bool {
    let events = crate::syscall::extended::epoll::check_fd_events_external(fd, EPOLLERR | EPOLLHUP);
    (events & (EPOLLERR | EPOLLHUP)) != 0
}

pub fn has_fd_error(fd: i32) -> bool {
    let events = crate::syscall::extended::epoll::check_fd_events_external(fd, EPOLLERR);
    (events & EPOLLERR) != 0
}

pub fn has_fd_hangup(fd: i32) -> bool {
    let events = crate::syscall::extended::epoll::check_fd_events_external(fd, EPOLLHUP);
    (events & EPOLLHUP) != 0
}

pub fn has_fd_priority_data(fd: i32) -> bool {
    let events = crate::syscall::extended::epoll::check_fd_events_external(fd, EPOLLPRI);
    (events & EPOLLPRI) != 0
}
