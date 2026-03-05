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

//! Buddy Allocator Constants
//!
//! Defines constants for the buddy allocator including:
//! - Order ranges for allocation sizes
//! - Alignment requirements
//! - Block size calculations

// ============================================================================
// ORDER CONFIGURATION
// ============================================================================

/// Maximum allocation order (2^20 = 1 MiB)
pub const MAX_ORDER: usize = 20;

/// Minimum allocation order (2^12 = 4 KiB = PAGE_SIZE)
pub const MIN_ORDER: usize = 12;

/// Number of free lists (one per order from MIN to MAX)
pub const FREE_LIST_COUNT: usize = MAX_ORDER - MIN_ORDER + 1;

// ============================================================================
// SIZE CONSTANTS
// ============================================================================

/// Minimum block size (4 KiB)
pub const MIN_BLOCK_SIZE: usize = 1 << MIN_ORDER;

/// Maximum block size (1 MiB)
pub const MAX_BLOCK_SIZE: usize = 1 << MAX_ORDER;

/// Page size (same as minimum block size)
pub const PAGE_SIZE: usize = 4096;

/// Page size as u64
pub const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

// ============================================================================
// ALIGNMENT REQUIREMENTS
// ============================================================================

/// Minimum allocation alignment
pub const MIN_ALIGNMENT: usize = PAGE_SIZE;

/// Maximum supported alignment
pub const MAX_ALIGNMENT: usize = MAX_BLOCK_SIZE;

// ============================================================================
// ALLOCATION FLAGS
// ============================================================================

/// Flag: Allocation should be zeroed
pub const ALLOC_FLAG_ZERO: u32 = 0x0001;

/// Flag: Allocation is for DMA
pub const ALLOC_FLAG_DMA: u32 = 0x0002;

/// Flag: Allocation is uncacheable
pub const ALLOC_FLAG_UNCACHED: u32 = 0x0004;

/// Flag: Allocation is write-combining
pub const ALLOC_FLAG_WRITE_COMBINE: u32 = 0x0008;

/// Flag: Allocation is for user space
pub const ALLOC_FLAG_USER: u32 = 0x0010;

/// Flag: Allocation is executable
pub const ALLOC_FLAG_EXEC: u32 = 0x0020;

// ============================================================================
// STATISTICS LIMITS
// ============================================================================

/// Maximum tracked allocation count
pub const MAX_ALLOCATION_COUNT: usize = usize::MAX - 1;

/// Maximum tracked memory usage
pub const MAX_MEMORY_USAGE: u64 = u64::MAX - 1;

// ============================================================================
// ORDER CALCULATION HELPERS
// ============================================================================

/// Returns the size for a given order.
#[inline]
pub const fn order_to_size(order: usize) -> usize {
    1 << order
}

/// Returns the order for a given size (rounds up).
#[inline]
pub const fn size_to_order(size: usize) -> usize {
    let size = if size < MIN_BLOCK_SIZE { MIN_BLOCK_SIZE } else { size };
    let mut order = MIN_ORDER;
    while (1 << order) < size && order < MAX_ORDER {
        order += 1;
    }
    order
}

/// Returns the buddy address for a block.
#[inline]
pub const fn buddy_address(addr: u64, order: usize) -> u64 {
    addr ^ (1u64 << order)
}
