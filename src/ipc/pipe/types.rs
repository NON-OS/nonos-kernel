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
use alloc::vec::Vec;

pub const PIPE_BUF_SIZE: usize = 65536;
pub(super) const MAX_PIPES: usize = 1024;
pub(super) const EAGAIN: i32 = 11;
pub(super) const EPIPE: i32 = 32;
pub(super) const EBADF: i32 = 9;

pub(super) struct Pipe {
    pub id: u32,
    pub buffer: Vec<u8>,
    pub read_pos: usize,
    pub write_pos: usize,
    pub bytes_available: usize,
    pub capacity: usize,
    pub read_closed: bool,
    pub write_closed: bool,
    pub read_nonblock: bool,
    pub write_nonblock: bool,
}

impl Pipe {
    pub fn new(id: u32, capacity: usize) -> Self {
        Self {
            id,
            buffer: vec![0u8; capacity],
            read_pos: 0,
            write_pos: 0,
            bytes_available: 0,
            capacity,
            read_closed: false,
            write_closed: false,
            read_nonblock: false,
            write_nonblock: false,
        }
    }

    pub fn pipe_id(&self) -> u32 {
        self.id
    }

    pub fn is_broken(&self) -> bool {
        self.write_closed && self.bytes_available == 0
    }

    pub fn space_available(&self) -> usize {
        self.capacity - self.bytes_available
    }
}
