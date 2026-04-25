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

use super::packet::PacketBuffer;

pub struct BufferPool {
    buffers: alloc::vec::Vec<PacketBuffer>,
    free_indices: alloc::collections::VecDeque<usize>,
    buffer_size: usize,
}

impl BufferPool {
    pub fn new(count: usize, buffer_size: usize) -> Result<Self, &'static str> {
        let mut buffers = alloc::vec::Vec::with_capacity(count);
        let mut free_indices = alloc::collections::VecDeque::with_capacity(count);
        for i in 0..count {
            buffers.push(PacketBuffer::new(buffer_size)?);
            free_indices.push_back(i);
        }
        Ok(Self { buffers, free_indices, buffer_size })
    }

    pub fn acquire(&mut self) -> Option<(usize, &mut PacketBuffer)> {
        let idx = self.free_indices.pop_front()?;
        let buf = &mut self.buffers[idx];
        if buf.acquire().is_err() {
            self.free_indices.push_back(idx);
            return None;
        }
        Some((idx, buf))
    }

    pub fn release(&mut self, idx: usize) {
        if idx < self.buffers.len() {
            self.buffers[idx].release();
            self.free_indices.push_back(idx);
        }
    }

    pub fn get(&self, idx: usize) -> Option<&PacketBuffer> {
        self.buffers.get(idx)
    }
    pub fn get_mut(&mut self, idx: usize) -> Option<&mut PacketBuffer> {
        self.buffers.get_mut(idx)
    }
    pub fn available(&self) -> usize {
        self.free_indices.len()
    }
    pub fn total(&self) -> usize {
        self.buffers.len()
    }
    pub fn buffer_size(&self) -> usize {
        self.buffer_size
    }
}
