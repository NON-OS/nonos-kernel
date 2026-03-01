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

pub const FD_SETSIZE: i32 = 1024;
pub const NFDBITS: usize = 64;

pub const POLLIN: i16 = 0x0001;
pub const POLLPRI: i16 = 0x0002;
pub const POLLOUT: i16 = 0x0004;
pub const POLLERR: i16 = 0x0008;
pub const POLLHUP: i16 = 0x0010;
pub const POLLNVAL: i16 = 0x0020;
pub const POLLRDNORM: i16 = 0x0040;
pub const POLLRDBAND: i16 = 0x0080;
pub const POLLWRNORM: i16 = 0x0100;
pub const POLLWRBAND: i16 = 0x0200;

pub const EINVAL: i32 = 22;
pub const EFAULT: i32 = 14;
pub const EINTR: i32 = 4;

#[repr(C)]
#[derive(Clone, Copy)]
pub struct FdSet {
    pub bits: [u64; FD_SETSIZE as usize / NFDBITS],
}

impl FdSet {
    pub fn new() -> Self {
        Self { bits: [0; FD_SETSIZE as usize / NFDBITS] }
    }

    pub fn isset(&self, fd: i32) -> bool {
        if fd < 0 || fd >= FD_SETSIZE {
            return false;
        }
        let idx = fd as usize / NFDBITS;
        let bit = fd as usize % NFDBITS;
        (self.bits[idx] & (1u64 << bit)) != 0
    }

    pub fn set(&mut self, fd: i32) {
        if fd >= 0 && fd < FD_SETSIZE {
            let idx = fd as usize / NFDBITS;
            let bit = fd as usize % NFDBITS;
            self.bits[idx] |= 1u64 << bit;
        }
    }

    pub fn zero(&mut self) {
        for i in 0..self.bits.len() {
            self.bits[i] = 0;
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timeval {
    pub tv_sec: i64,
    pub tv_usec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct Timespec {
    pub tv_sec: i64,
    pub tv_nsec: i64,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct PollFd {
    pub fd: i32,
    pub events: i16,
    pub revents: i16,
}
