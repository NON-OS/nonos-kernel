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

pub use crate::syscall::extended::select::{
    PollFd, FD_SETSIZE, POLLERR, POLLHUP, POLLIN, POLLNVAL, POLLOUT, POLLPRI, POLLRDBAND,
    POLLRDNORM, POLLWRBAND, POLLWRNORM,
};

pub fn sys_poll(fds_ptr: usize, nfds: usize, timeout_ms: i32) -> i64 {
    crate::syscall::extended::select::handle_poll(fds_ptr as u64, nfds as u32, timeout_ms).value
}

pub fn sys_ppoll(
    fds_ptr: usize,
    nfds: usize,
    timeout_ptr: usize,
    sigmask: usize,
    sigsetsize: usize,
) -> i64 {
    crate::syscall::extended::select::handle_ppoll(
        fds_ptr as u64,
        nfds as u32,
        timeout_ptr as u64,
        sigmask as u64,
        sigsetsize as u64,
    )
    .value
}

pub fn sys_select(
    nfds: i32,
    readfds: usize,
    writefds: usize,
    exceptfds: usize,
    timeout: usize,
) -> i64 {
    crate::syscall::extended::select::handle_select(
        nfds,
        readfds as u64,
        writefds as u64,
        exceptfds as u64,
        timeout as u64,
    )
    .value
}

pub fn sys_pselect6(
    nfds: i32,
    readfds: usize,
    writefds: usize,
    exceptfds: usize,
    timeout: usize,
    sigmask_ptr: usize,
) -> i64 {
    crate::syscall::extended::select::handle_pselect6(
        nfds,
        readfds as u64,
        writefds as u64,
        exceptfds as u64,
        timeout as u64,
        sigmask_ptr as u64,
    )
    .value
}

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct FdSet {
    pub bits: [u64; FD_SETSIZE / 64],
}

impl FdSet {
    pub fn new() -> Self {
        Self { bits: [0; FD_SETSIZE / 64] }
    }
    pub fn set(&mut self, fd: i32) {
        if fd >= 0 && (fd as usize) < FD_SETSIZE {
            self.bits[fd as usize / 64] |= 1 << (fd % 64);
        }
    }
    pub fn clear(&mut self, fd: i32) {
        if fd >= 0 && (fd as usize) < FD_SETSIZE {
            self.bits[fd as usize / 64] &= !(1 << (fd % 64));
        }
    }
    pub fn is_set(&self, fd: i32) -> bool {
        fd >= 0
            && (fd as usize) < FD_SETSIZE
            && (self.bits[fd as usize / 64] & (1 << (fd % 64))) != 0
    }
    pub fn zero(&mut self) {
        for b in self.bits.iter_mut() {
            *b = 0;
        }
    }
}
