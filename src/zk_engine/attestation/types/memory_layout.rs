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

use crate::memory::VirtAddr;
use alloc::vec::Vec;

#[derive(Debug, Clone)]
pub struct MemoryLayout {
    pub kernel_start: VirtAddr,
    pub kernel_end: VirtAddr,
    pub user_start: VirtAddr,
    pub user_end: VirtAddr,
    pub heap_start: VirtAddr,
    pub heap_end: VirtAddr,
}

impl Default for MemoryLayout {
    fn default() -> Self {
        Self {
            kernel_start: VirtAddr::new(0),
            kernel_end: VirtAddr::new(0),
            user_start: VirtAddr::new(0),
            user_end: VirtAddr::new(0),
            heap_start: VirtAddr::new(0),
            heap_end: VirtAddr::new(0),
        }
    }
}

impl MemoryLayout {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut data = Vec::new();
        data.extend_from_slice(&self.kernel_start.as_u64().to_le_bytes());
        data.extend_from_slice(&self.kernel_end.as_u64().to_le_bytes());
        data.extend_from_slice(&self.user_start.as_u64().to_le_bytes());
        data.extend_from_slice(&self.user_end.as_u64().to_le_bytes());
        data.extend_from_slice(&self.heap_start.as_u64().to_le_bytes());
        data.extend_from_slice(&self.heap_end.as_u64().to_le_bytes());
        data
    }
}
