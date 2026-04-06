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

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AioOpcode {
    Pread = 0,
    Pwrite = 1,
    Fsync = 2,
    Fdsync = 3,
    Poll = 5,
    Noop = 6,
    Preadv = 7,
    Pwritev = 8,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct Iocb {
    pub aio_data: u64,
    pub aio_key: u32,
    pub aio_rw_flags: u32,
    pub aio_lio_opcode: u16,
    pub aio_reqprio: i16,
    pub aio_fildes: u32,
    pub aio_buf: u64,
    pub aio_nbytes: u64,
    pub aio_offset: i64,
    pub aio_reserved2: u64,
    pub aio_flags: u32,
    pub aio_resfd: u32,
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Default)]
pub struct IoEvent {
    pub data: u64,
    pub obj: u64,
    pub res: i64,
    pub res2: i64,
}

impl Iocb {
    pub fn opcode(&self) -> Option<AioOpcode> {
        match self.aio_lio_opcode {
            0 => Some(AioOpcode::Pread),
            1 => Some(AioOpcode::Pwrite),
            2 => Some(AioOpcode::Fsync),
            3 => Some(AioOpcode::Fdsync),
            5 => Some(AioOpcode::Poll),
            6 => Some(AioOpcode::Noop),
            7 => Some(AioOpcode::Preadv),
            8 => Some(AioOpcode::Pwritev),
            _ => None,
        }
    }
}

impl IoEvent {
    pub fn new(data: u64, obj: u64, res: i64) -> Self {
        Self { data, obj, res, res2: 0 }
    }

    pub fn error(data: u64, obj: u64, errno: i32) -> Self {
        Self { data, obj, res: -(errno as i64), res2: 0 }
    }

    pub fn success(data: u64, obj: u64, bytes: i64) -> Self {
        Self { data, obj, res: bytes, res2: 0 }
    }

    pub fn is_error(&self) -> bool {
        self.res < 0
    }
}

impl Iocb {
    pub fn fd(&self) -> i32 {
        self.aio_fildes as i32
    }

    pub fn buffer(&self) -> u64 {
        self.aio_buf
    }

    pub fn count(&self) -> usize {
        self.aio_nbytes as usize
    }

    pub fn offset(&self) -> i64 {
        self.aio_offset
    }

    pub fn data(&self) -> u64 {
        self.aio_data
    }
}

pub const MAX_AIO_EVENTS: usize = 65536;
pub const IOCB_FLAG_RESFD: u32 = 1;
pub const IOCB_FLAG_IOPRIO: u32 = 2;
