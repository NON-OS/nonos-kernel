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

pub struct PipeBuffer {
    data: Vec<u8>,
    read_pos: usize,
}

impl PipeBuffer {
    pub fn new() -> Self {
        Self { data: Vec::with_capacity(PIPE_BUF_SIZE), read_pos: 0 }
    }

    pub fn available_read(&self) -> usize {
        self.data.len() - self.read_pos
    }

    pub fn available_write(&self) -> usize {
        PIPE_BUF_SIZE - self.data.len()
    }

    pub fn read(&mut self, buf: &mut [u8]) -> usize {
        let available = self.available_read();
        let to_read = buf.len().min(available);
        if to_read > 0 {
            buf[..to_read].copy_from_slice(&self.data[self.read_pos..self.read_pos + to_read]);
            self.read_pos += to_read;
            if self.read_pos == self.data.len() {
                self.data.clear();
                self.read_pos = 0;
            }
        }
        to_read
    }

    pub fn write(&mut self, buf: &[u8]) -> usize {
        let available = self.available_write();
        let to_write = buf.len().min(available);
        if to_write > 0 {
            self.data.extend_from_slice(&buf[..to_write]);
        }
        to_write
    }

    pub fn peek(&self, buf: &mut [u8]) -> usize {
        let available = self.available_read();
        let to_read = buf.len().min(available);
        if to_read > 0 {
            buf[..to_read].copy_from_slice(&self.data[self.read_pos..self.read_pos + to_read]);
        }
        to_read
    }

    pub fn is_empty(&self) -> bool {
        self.available_read() == 0
    }

    pub fn is_full(&self) -> bool {
        self.available_write() == 0
    }
}

impl Default for PipeBuffer {
    fn default() -> Self {
        Self::new()
    }
}
