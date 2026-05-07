// NØNOS Operating System
// Copyright (C) 2026 NØNOS Contributors
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

use crate::crypto::sig::CapsuleMetadata;
use crate::loader::types::memory;

use super::kernel::KernelImage;
use super::segment_layout::{KernelSegmentLayout, MAX_KERNEL_SEGMENTS};

pub struct KernelImageBuilder {
    address: usize,
    size: usize,
    entry_point: usize,
    metadata: CapsuleMetadata,
    allocations: [(u64, usize); memory::MAX_ALLOCATIONS],
    alloc_count: usize,
}

impl Default for KernelImageBuilder {
    fn default() -> Self {
        Self::new()
    }
}

impl KernelImageBuilder {
    pub fn new() -> Self {
        Self {
            address: 0,
            size: 0,
            entry_point: 0,
            metadata: CapsuleMetadata::default(),
            allocations: [(0, 0); memory::MAX_ALLOCATIONS],
            alloc_count: 0,
        }
    }

    pub fn address(mut self, address: usize) -> Self {
        self.address = address;
        self
    }

    pub fn size(mut self, size: usize) -> Self {
        self.size = size;
        self
    }

    pub fn entry_point(mut self, entry_point: usize) -> Self {
        self.entry_point = entry_point;
        self
    }

    pub fn metadata(mut self, metadata: CapsuleMetadata) -> Self {
        self.metadata = metadata;
        self
    }

    pub fn allocations(
        mut self,
        allocations: [(u64, usize); memory::MAX_ALLOCATIONS],
        count: usize,
    ) -> Self {
        self.allocations = allocations;
        self.alloc_count = count;
        self
    }

    pub fn payload_hash(mut self, hash: [u8; 32]) -> Self {
        self.metadata.payload_hash = hash;
        self
    }

    pub fn payload_len(mut self, len: usize) -> Self {
        self.metadata.len_payload = len;
        self
    }

    pub fn build(self) -> KernelImage {
        KernelImage {
            address: self.address,
            size: self.size,
            entry_point: self.entry_point,
            virt_base: 0,
            segments: [KernelSegmentLayout::default(); MAX_KERNEL_SEGMENTS],
            segment_count: 0,
            metadata: self.metadata,
            allocations: self.allocations,
            alloc_count: self.alloc_count,
        }
    }
}
