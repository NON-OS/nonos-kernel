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
// ============================================================================
// ORDER CONFIGURATION
// ============================================================================
pub const MAX_ORDER: usize = 20;
pub const MIN_ORDER: usize = 12;
pub const FREE_LIST_COUNT: usize = MAX_ORDER - MIN_ORDER + 1;
// ============================================================================
// SIZE CONSTANTS
// ============================================================================
pub const MIN_BLOCK_SIZE: usize = 1 << MIN_ORDER;
pub const MAX_BLOCK_SIZE: usize = 1 << MAX_ORDER;
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;
// ============================================================================
// ALIGNMENT REQUIREMENTS
// ============================================================================
pub const MIN_ALIGNMENT: usize = PAGE_SIZE;
pub const MAX_ALIGNMENT: usize = MAX_BLOCK_SIZE;
// ============================================================================
// ALLOCATION FLAGS
// ============================================================================
pub const ALLOC_FLAG_ZERO: u32 = 0x0001;
pub const ALLOC_FLAG_DMA: u32 = 0x0002;
pub const ALLOC_FLAG_UNCACHED: u32 = 0x0004;
pub const ALLOC_FLAG_WRITE_COMBINE: u32 = 0x0008;
pub const ALLOC_FLAG_USER: u32 = 0x0010;
pub const ALLOC_FLAG_EXEC: u32 = 0x0020;
// ============================================================================
// STATISTICS LIMITS
// ============================================================================
pub const MAX_ALLOCATION_COUNT: usize = usize::MAX - 1;
pub const MAX_MEMORY_USAGE: u64 = u64::MAX - 1;
// ============================================================================
// ORDER CALCULATION HELPERS
// ============================================================================
#[inline]
pub const fn order_to_size(order: usize) -> usize {
    1 << order
}
#[inline]
pub const fn size_to_order(size: usize) -> usize {
    let size = if size < MIN_BLOCK_SIZE { MIN_BLOCK_SIZE } else { size };
    let mut order = MIN_ORDER;
    while (1 << order) < size && order < MAX_ORDER {
        order += 1;
    }
    order
}
#[inline]
pub const fn buddy_address(addr: u64, order: usize) -> u64 {
    addr ^ (1u64 << order)
}
