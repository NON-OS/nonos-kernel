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

//! DMA Types

use x86_64::{PhysAddr, VirtAddr};

use super::constants::*;
use crate::memory::layout;

// ============================================================================
// DMA DIRECTION
// ============================================================================

/// Direction of DMA transfer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DmaDirection {
    /// Data flows from memory to device
    ToDevice,
    /// Data flows from device to memory
    FromDevice,
    /// Data flows in both directions
    Bidirectional,
}

impl DmaDirection {
    /// Returns true if data is written to device.
    pub const fn writes_to_device(&self) -> bool {
        matches!(self, Self::ToDevice | Self::Bidirectional)
    }

    /// Returns true if data is read from device.
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

/// Constraints for DMA allocation.
#[derive(Debug, Clone, Copy)]
pub struct DmaConstraints {
    /// Required alignment for DMA buffer
    pub alignment: usize,
    /// Maximum segment size
    pub max_segment_size: usize,
    /// Require address below 4 GiB
    pub dma32_only: bool,
    /// Require cache-coherent mapping
    pub coherent: bool,
}

impl DmaConstraints {
    /// Creates default constraints (page-aligned, coherent).
    pub const fn new() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: false,
            coherent: true,
        }
    }

    /// Creates DMA32-only constraints.
    pub const fn dma32() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: true,
            coherent: true,
        }
    }

    /// Creates non-coherent constraints.
    pub const fn non_coherent() -> Self {
        Self {
            alignment: DEFAULT_ALIGNMENT,
            max_segment_size: DEFAULT_MAX_SEGMENT_SIZE,
            dma32_only: false,
            coherent: false,
        }
    }

    /// Returns true if a physical address satisfies these constraints.
    pub fn is_satisfied(&self, phys_addr: u64, size: usize) -> bool {
        // Check alignment
        if phys_addr % self.alignment as u64 != 0 {
            return false;
        }

        // Check DMA32 limit
        if self.dma32_only && !is_range_dma32_compatible(phys_addr, size) {
            return false;
        }

        // Check max segment size
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

/// A coherent DMA memory region.
#[derive(Debug, Clone, Copy)]
pub struct DmaRegion {
    /// Virtual address accessible by CPU
    pub virt_addr: VirtAddr,
    /// Physical address for DMA
    pub phys_addr: PhysAddr,
    /// Size in bytes
    pub size: usize,
    /// Whether this is a coherent mapping
    pub coherent: bool,
    /// Whether this is DMA32-compatible
    pub dma32_compatible: bool,
}

impl DmaRegion {
    /// Creates a new DMA region.
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

    /// Returns the DMA address for the device.
    pub const fn dma_addr(&self) -> u64 {
        self.phys_addr.as_u64()
    }

    /// Returns a pointer to the buffer.
    pub fn as_ptr(&self) -> *const u8 {
        self.virt_addr.as_ptr()
    }

    /// Returns a mutable pointer to the buffer.
    pub fn as_mut_ptr(&self) -> *mut u8 {
        self.virt_addr.as_mut_ptr()
    }

    /// Returns the buffer as a slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure the region is valid and properly initialized.
    pub unsafe fn as_slice(&self) -> &[u8] { unsafe {
        core::slice::from_raw_parts(self.as_ptr(), self.size)
    }}

    /// Returns the buffer as a mutable slice.
    ///
    /// # Safety
    ///
    /// The caller must ensure the region is valid and properly initialized.
    pub unsafe fn as_mut_slice(&mut self) -> &mut [u8] { unsafe {
        core::slice::from_raw_parts_mut(self.as_mut_ptr(), self.size)
    }}

    /// Zeroes the buffer.
    pub fn zero(&mut self) {
        // SAFETY: We own this region
        unsafe {
            core::ptr::write_bytes(self.as_mut_ptr(), 0, self.size);
        }
    }

    /// Returns true if this region is DMA32-compatible.
    pub const fn is_dma32(&self) -> bool {
        self.dma32_compatible
    }

    /// Returns the number of pages in this region.
    pub const fn page_count(&self) -> usize {
        pages_needed(self.size)
    }
}

// ============================================================================
// STREAMING MAPPING
// ============================================================================

/// A streaming DMA mapping.
#[derive(Debug, Clone, Copy)]
pub struct StreamingMapping {
    /// Unique mapping identifier
    pub mapping_id: u64,
    /// Original buffer virtual address
    pub buffer_va: VirtAddr,
    /// DMA address for the device
    pub dma_addr: PhysAddr,
    /// Size of the mapping
    pub size: usize,
    /// Transfer direction
    pub direction: DmaDirection,
    /// Bounce buffer if one was allocated
    pub bounce_buffer: Option<DmaRegion>,
}

impl StreamingMapping {
    /// Creates a new streaming mapping.
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

    /// Returns true if a bounce buffer is being used.
    pub const fn uses_bounce_buffer(&self) -> bool {
        self.bounce_buffer.is_some()
    }

    /// Returns the DMA address for the device.
    pub const fn dma_address(&self) -> u64 {
        self.dma_addr.as_u64()
    }
}

// ============================================================================
// DMA STATS SNAPSHOT
// ============================================================================

/// Snapshot of DMA statistics.
#[derive(Debug, Clone, Default)]
pub struct DmaStatsSnapshot {
    /// Number of coherent allocations
    pub coherent_allocations: usize,
    /// Number of active streaming mappings
    pub streaming_mappings: usize,
    /// Number of bounce buffers in use
    pub bounce_buffer_usage: usize,
    /// Total DMA memory allocated (bytes)
    pub total_dma_memory: u64,
    /// Total DMA operations performed
    pub dma_operations: u64,
}

impl DmaStatsSnapshot {
    /// Creates an empty stats snapshot.
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
