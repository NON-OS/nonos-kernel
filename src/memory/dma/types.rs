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

use x86_64::{PhysAddr, VirtAddr};
use super::constants::*;
use crate::memory::layout;
// ============================================================================
// DMA DIRECTION
// ============================================================================
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    ToDevice,
    FromDevice,
    Bidirectional,
}

impl DmaDirection {
    pub const fn writes_to_device(&self) -> bool {
        matches!(self, Self::ToDevice | Self::Bidirectional)
    }

    pub const fn reads_from_device(&self) -> bool {
        matches!(self, Self::FromDevice | Self::Bidirectional)
    }
}

impl Default for DmaDirection {
    fn default() -> Self {
        Self::Bidirectional
    }
}
// ============================================================================
// DMA CONSTRAINTS
// ============================================================================
#[derive(Debug, Clone, Copy)]
pub struct DmaConstraints {
    pub alignment: usize,
    pub max_segment_size: usize,
    pub dma32_only: bool,
    pub coherent: bool,
}

impl DmaConstraints {
    pub const fn new() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: false,
            coherent: true,
        }
    }

    pub const fn dma32() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: true,
            coherent: true,
        }
    }

    pub const fn non_coherent() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: false,
            coherent: false,
        }
    }

    pub fn is_satisfied(&self, phys_addr: u64, size: usize) -> bool {
        if phys_addr % self.alignment as u64 != 0 {
            return false;
        }

        if self.dma32_only && !is_range_dma32_compatible(phys_addr, size) {
            return false;
        }

        if size > self.max_segment_size {
            return false;
        }

        true
    }
}

impl Default for DmaConstraints {
    fn default() -> Self {
        Self {
            alignment: layout::PAGE_SIZE,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: false,
            coherent: true,
        }
    }
}
// ============================================================================
// DMA REGION
// ============================================================================
#[derive(Debug, Clone, Copy)]
pub struct DmaRegion {
    pub virt_addr: VirtAddr,
    pub phys_addr: PhysAddr,
    pub size: usize,
    pub coherent: bool,
    pub dma32_compatible: bool,
}

impl DmaRegion {
    pub const fn new(
        virt_addr: VirtAddr,
        phys_addr: PhysAddr,
        size: usize,
        coherent: bool,
        dma32_compatible: bool,
    ) -> Self {
        Self {
            virt_addr,
            phys_addr,
            size,
            coherent,
            dma32_compatible,
        }
    }

    pub const fn dma_addr(&self) -> u64 {
        self.phys_addr.as_u64()
    }

    pub fn as_ptr(&self) -> *const u8 {
        self.virt_addr.as_ptr()
    }

    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.virt_addr.as_mut_ptr()
    }

    /// Returns the buffer as a slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure the region is valid and properly initialized.
    pub unsafe fn as_slice(&self) -> &[u8] {
        core::slice::from_raw_parts(self.as_ptr(), self.size)
    }

    /// Returns the buffer as a mutable slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure the region is valid and properly initialized.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] {
        core::slice::from_raw_parts_mut(self.as_mut_ptr(), self.size)
    }

    /// Zeroes the buffer.
    pub fn zero(&mut self) {
        // SAFETY: We own this region
        unsafe {
            core::ptr::write_bytes(self.as_mut_ptr(), 0, self.size);
        }
    }

    pub const fn is_dma32(&self) -> bool {
        self.dma32_compatible
    }

    pub const fn page_count(&self) -> usize {
        pages_needed(self.size)
    }
}
// ============================================================================
// STREAMING MAPPING
// ============================================================================
#[derive(Debug, Clone, Copy)]
pub struct StreamingMapping {
    pub mapping_id: u64,
    pub buffer_va: VirtAddr,
    pub dma_addr: PhysAddr,
    pub size: usize,
    pub direction: DmaDirection,
    pub bounce_buffer: Option<DmaRegion>,
}

impl StreamingMapping {
    pub const fn new(
        mapping_id: u64,
        buffer_va: VirtAddr,
        dma_addr: PhysAddr,
        size: usize,
        direction: DmaDirection,
        bounce_buffer: Option<DmaRegion>,
    ) -> Self {
        Self {
            mapping_id,
            buffer_va,
            dma_addr,
            size,
            direction,
            bounce_buffer,
        }
    }

    pub const fn uses_bounce_buffer(&self) -> bool {
        self.bounce_buffer.is_some()
    }

  pub const fn dma_address(&self) -> u64 {
        self.dma_addr.as_u64()
    }
}

// ============================================================================
// DMA STATS SNAPSHOT
// ============================================================================
#[derive(Debug, Clone, Default)]
pub struct DmaStatsSnapshot {
    pub coherent_allocations: usize,
    pub streaming_mappings: usize,
    pub bounce_buffer_usage: usize,
    pub total_dma_memory: u64,
    pub dma_operations: u64,
}

impl DmaStatsSnapshot {
    pub const fn new() -> Self {
        Self {
            coherent_allocations: 0,
            streaming_mappings: 0,
            bounce_buffer_usage: 0,
            total_dma_memory: 0,
            dma_operations: 0,
        }
    }
}
