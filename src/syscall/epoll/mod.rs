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

pub use crate::syscall::extended::epoll::{
    close_epoll, fd_to_epoll_id, is_epoll_fd, EpollEvent, EPOLLERR, EPOLLET, EPOLLEXCLUSIVE,
    EPOLLHUP, EPOLLIN, EPOLLMSG, EPOLLONESHOT, EPOLLOUT, EPOLLPRI, EPOLLRDBAND, EPOLLRDHUP,
    EPOLLRDNORM, EPOLLWAKEUP, EPOLLWRBAND, EPOLLWRNORM, EPOLL_CLOEXEC, EPOLL_CTL_ADD,
    EPOLL_CTL_DEL, EPOLL_CTL_MOD,
};

pub fn sys_epoll_create(size: i32) -> i64 {
    if size <= 0 {
        return -22;
    }
    sys_epoll_create1(0)
}

pub fn sys_epoll_create1(flags: i32) -> i64 {
    crate::syscall::extended::epoll::handle_epoll_create1(flags).value
}

pub fn sys_epoll_ctl(epfd: i32, op: i32, fd: i32, event_ptr: usize) -> i64 {
    crate::syscall::extended::epoll::handle_epoll_ctl(epfd, op, fd, event_ptr as u64).value
}

pub fn sys_epoll_wait(epfd: i32, events_ptr: usize, maxevents: i32, timeout: i32) -> i64 {
    crate::syscall::extended::epoll::handle_epoll_wait(epfd, events_ptr as u64, maxevents, timeout)
        .value
}

pub fn sys_epoll_pwait(
    epfd: i32,
    events_ptr: usize,
    maxevents: i32,
    timeout: i32,
    sigmask: usize,
    sigsetsize: usize,
) -> i64 {
    crate::syscall::extended::epoll::handle_epoll_pwait(
        epfd,
        events_ptr as u64,
        maxevents,
        timeout,
        sigmask as u64,
        sigsetsize as u64,
    )
    .value
}

pub fn sys_epoll_pwait2(
    epfd: i32,
    events_ptr: usize,
    maxevents: i32,
    timeout_ptr: usize,
    sigmask: usize,
    sigsetsize: usize,
) -> i64 {
    let timeout_ms = if timeout_ptr == 0 {
        -1
    } else {
        #[repr(C)]
        struct Ts {
            sec: i64,
            nsec: i64,
        }
        let ts = unsafe { core::ptr::read(timeout_ptr as *const Ts) };
        ((ts.sec * 1000) + (ts.nsec / 1_000_000)) as i32
    };
    sys_epoll_pwait(epfd, events_ptr, maxevents, timeout_ms, sigmask, sigsetsize)
}
