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

#[derive(Debug, Clone)]
pub struct KernelImage {
    pub address: usize,
    pub size: usize,
    pub entry_point: usize,
    pub metadata: CapsuleMetadata,
    pub allocations: [(u64, usize); memory::MAX_ALLOCATIONS],
    pub alloc_count: usize,
}

impl KernelImage {
    pub fn new(address: usize, size: usize, entry_point: usize, metadata: CapsuleMetadata) -> Self {
        Self {
            address,
            size,
            entry_point,
            metadata,
            allocations: [(0, 0); memory::MAX_ALLOCATIONS],
            alloc_count: 0,
        }
    }

    pub fn with_allocations(
        address: usize,
        size: usize,
        entry_point: usize,
        metadata: CapsuleMetadata,
        allocations: [(u64, usize); memory::MAX_ALLOCATIONS],
        alloc_count: usize,
    ) -> Self {
        Self {
            address,
            size,
            entry_point,
            metadata,
            allocations,
            alloc_count,
        }
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.address as *const u8
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.address as *mut u8
    }

    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.as_ptr(), self.size)
    }

    pub fn end_address(&self) -> usize {
        self.address + self.size
    }

    pub fn contains(&self, addr: usize) -> bool {
        addr >= self.address && addr < self.end_address()
    }

    pub fn page_count(&self) -> usize {
        memory::pages_needed(self.size)
    }

    pub fn total_allocated_pages(&self) -> usize {
        self.allocations[..self.alloc_count]
            .iter()
            .map(|(_, pages)| *pages)
            .sum()
    }

    pub fn is_entry_valid(&self) -> bool {
        self.contains(self.entry_point)
    }

    pub fn payload_hash(&self) -> &[u8; 32] {
        &self.metadata.payload_hash
    }

    pub fn is_signed(&self) -> bool {
        self.metadata.len_sig > 0
    }

    pub fn signer_key_id(&self) -> Option<[u8; 32]> {
        self.metadata.signer_keyid
    }
}

impl Default for KernelImage {
    fn default() -> Self {
        Self {
            address: 0,
            size: 0,
            entry_point: 0,
            metadata: CapsuleMetadata::default(),
            allocations: [(0, 0); memory::MAX_ALLOCATIONS],
            alloc_count: 0,
        }
    }
}

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
            metadata: self.metadata,
            allocations: self.allocations,
            alloc_count: self.alloc_count,
        }
    }
}

#[derive(Debug)]
pub struct KernelInfo {
    pub load_address: u64,
    pub virtual_address: u64,
    pub entry_point: u64,
    pub text_size: usize,
    pub data_size: usize,
    pub bss_size: usize,
    pub total_size: usize,
    pub is_pie: bool,
    pub has_relocations: bool,
    pub segment_count: usize,
}

impl KernelInfo {
    pub fn from_image(image: &KernelImage, is_pie: bool) -> Self {
        Self {
            load_address: image.address as u64,
            virtual_address: image.address as u64,
            entry_point: image.entry_point as u64,
            text_size: 0,
            data_size: 0,
            bss_size: 0,
            total_size: image.size,
            is_pie,
            has_relocations: false,
            segment_count: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_kernel_image_contains() {
        let image = KernelImage::new(0x100000, 0x10000, 0x100000, CapsuleMetadata::default());

        assert!(image.contains(0x100000));
        assert!(image.contains(0x10FFFF));
        assert!(!image.contains(0x110000));
        assert!(!image.contains(0x0FFFFF));
    }

    #[test]
    fn test_kernel_image_entry_valid() {
        let mut image = KernelImage::new(0x100000, 0x10000, 0x100000, CapsuleMetadata::default());
        assert!(image.is_entry_valid());

        image.entry_point = 0x200000;
        assert!(!image.is_entry_valid());
    }

    #[test]
    fn test_builder() {
        let image = KernelImageBuilder::new()
            .address(0x100000)
            .size(0x10000)
            .entry_point(0x101000)
            .build();

        assert_eq!(image.address, 0x100000);
        assert_eq!(image.size, 0x10000);
        assert_eq!(image.entry_point, 0x101000);
    }
}
