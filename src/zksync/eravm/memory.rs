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

use alloc::vec::Vec;

const PAGE_SIZE: usize = 4096;
const MAX_MEMORY: usize = 1 << 24;

pub struct VmMemory {
    data: Vec<u8>,
}

impl VmMemory {
    pub fn new() -> Self {
        Self { data: Vec::new() }
    }

    pub fn with_capacity(cap: usize) -> Self {
        Self { data: Vec::with_capacity(cap.min(MAX_MEMORY)) }
    }

    fn expand_to(&mut self, size: usize) {
        if size > self.data.len() && size <= MAX_MEMORY {
            let aligned = (size + PAGE_SIZE - 1) / PAGE_SIZE * PAGE_SIZE;
            self.data.resize(aligned.min(MAX_MEMORY), 0);
        }
    }

    pub fn load(&mut self, offset: usize, size: usize) -> &[u8] {
        self.expand_to(offset + size);
        let end = (offset + size).min(self.data.len());
        &self.data[offset.min(self.data.len())..end]
    }

    pub fn store(&mut self, offset: usize, data: &[u8]) {
        self.expand_to(offset + data.len());
        let end = (offset + data.len()).min(self.data.len());
        let copy_len = end.saturating_sub(offset);
        self.data[offset..end].copy_from_slice(&data[..copy_len]);
    }

    pub fn load_u256(&mut self, offset: usize) -> [u8; 32] {
        let mut result = [0u8; 32];
        let slice = self.load(offset, 32);
        let copy_len = slice.len().min(32);
        result[..copy_len].copy_from_slice(&slice[..copy_len]);
        result
    }

    pub fn store_u256(&mut self, offset: usize, value: &[u8; 32]) {
        self.store(offset, value);
    }

    pub fn size(&self) -> usize {
        self.data.len()
    }
    pub fn clear(&mut self) {
        self.data.clear();
    }
}

impl Default for VmMemory {
    fn default() -> Self {
        Self::new()
    }
}
