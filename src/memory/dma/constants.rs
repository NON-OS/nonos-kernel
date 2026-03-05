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

//! DMA Constants

use crate::memory::layout;

// ============================================================================
// SIZE CONSTANTS
// ============================================================================

/// Default DMA alignment (page-aligned)
pub const DEFAULT_ALIGNMENT: usize = layout::PAGE_SIZE;

/// Default maximum segment size (1 MiB)
pub const DEFAULT_MAX_SEGMENT_SIZE: usize = 1024 * 1024;

/// DMA32 address limit (4 GiB)
pub const DMA32_LIMIT: u64 = 1u64 << 32;

/// Minimum DMA allocation size
pub const MIN_DMA_SIZE: usize = 1;

/// Maximum DMA allocation size (256 MiB)
pub const MAX_DMA_SIZE: usize = 256 * 1024 * 1024;

// ============================================================================
// ADDRESS SPACE
// ============================================================================

/// Base address for DMA virtual address space
pub const DMA_VADDR_BASE: u64 = layout::DMA_BASE;

/// Size of DMA virtual address space
pub const DMA_VADDR_SIZE: u64 = layout::DMA_SIZE;

/// End address for DMA virtual address space
pub const DMA_VADDR_END: u64 = DMA_VADDR_BASE + DMA_VADDR_SIZE;

// ============================================================================
// PAGE FLAGS
// ============================================================================

/// PTE flags for coherent DMA mapping (present + writable)
pub const PTE_DMA_COHERENT: u64 = 0x03;

/// PTE cache disable flag
pub const PTE_CACHE_DISABLE: u64 = 0x10;

/// PTE flags for non-coherent DMA mapping
pub const PTE_DMA_NON_COHERENT: u64 = PTE_DMA_COHERENT | PTE_CACHE_DISABLE;

// ============================================================================
// POOL CONSTANTS
// ============================================================================

/// Default pool region size
pub const DEFAULT_POOL_REGION_SIZE: usize = layout::PAGE_SIZE;

/// Maximum pool capacity
pub const MAX_POOL_CAPACITY: usize = 1024;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Aligns a value up to the given alignment.
#[inline]
pub const fn align_up(value: usize, align: usize) -> usize {
    (value + align - 1) & !(align - 1)
}

/// Aligns a value down to the given alignment.
#[inline]
pub const fn align_down(value: usize, align: usize) -> usize {
    value & !(align - 1)
}

/// Checks if a value is aligned.
#[inline]
pub const fn is_aligned(value: usize, align: usize) -> bool {
    value & (align - 1) == 0
}

/// Calculates pages needed for a size.
#[inline]
pub const fn pages_needed(size: usize) -> usize {
    (size + layout::PAGE_SIZE - 1) / layout::PAGE_SIZE
}

/// Checks if a physical address is within DMA32 limit.
#[inline]
pub const fn is_dma32_compatible(phys_addr: u64) -> bool {
    phys_addr < DMA32_LIMIT
}

/// Checks if a range is within DMA32 limit.
#[inline]
pub const fn is_range_dma32_compatible(phys_addr: u64, size: usize) -> bool {
    phys_addr + size as u64 <= DMA32_LIMIT
}
