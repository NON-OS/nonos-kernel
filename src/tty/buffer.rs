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

use alloc::collections::VecDeque;
use alloc::vec::Vec;

const TTY_BUFFER_SIZE: usize = 4096;
const FLIP_BUFFER_SIZE: usize = 512;

pub struct TtyBuffer {
    data: VecDeque<u8>,
    capacity: usize,
}

impl TtyBuffer {
    pub const fn new() -> Self {
        Self { data: VecDeque::new(), capacity: TTY_BUFFER_SIZE }
    }

    pub fn push(&mut self, byte: u8) -> bool {
        if self.data.len() < self.capacity {
            self.data.push_back(byte);
            true
        } else {
            false
        }
    }

    pub fn push_bytes(&mut self, bytes: &[u8]) -> usize {
        let available = self.capacity - self.data.len();
        let to_push = bytes.len().min(available);
        for &b in &bytes[..to_push] {
            self.data.push_back(b);
        }
        to_push
    }

    pub fn pop(&mut self) -> Option<u8> {
        self.data.pop_front()
    }
    pub fn len(&self) -> usize {
        self.data.len()
    }
    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }
    pub fn clear(&mut self) {
        self.data.clear();
    }
    pub fn available(&self) -> usize {
        self.capacity - self.data.len()
    }
}

pub struct TtyFlipBuffer {
    buffers: [Vec<u8>; 2],
    flags: [Vec<u8>; 2],
    active: usize,
    count: [usize; 2],
}

impl TtyFlipBuffer {
    pub fn new() -> Self {
        Self {
            buffers: [Vec::with_capacity(FLIP_BUFFER_SIZE), Vec::with_capacity(FLIP_BUFFER_SIZE)],
            flags: [Vec::with_capacity(FLIP_BUFFER_SIZE), Vec::with_capacity(FLIP_BUFFER_SIZE)],
            active: 0,
            count: [0, 0],
        }
    }

    pub fn push(&mut self, byte: u8, flag: u8) -> bool {
        if self.count[self.active] < FLIP_BUFFER_SIZE {
            self.buffers[self.active].push(byte);
            self.flags[self.active].push(flag);
            self.count[self.active] += 1;
            true
        } else {
            false
        }
    }

    pub fn flip(&mut self) -> (&[u8], &[u8]) {
        let old = self.active;
        self.active = 1 - self.active;
        self.buffers[self.active].clear();
        self.flags[self.active].clear();
        self.count[self.active] = 0;
        (&self.buffers[old], &self.flags[old])
    }

    pub fn current_count(&self) -> usize {
        self.count[self.active]
    }
}
