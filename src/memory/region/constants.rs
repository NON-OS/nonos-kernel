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

//! Region Constants

use crate::memory::layout;

// ============================================================================
// FLAG BITS
// ============================================================================

/// Readable flag bit
pub const FLAG_READABLE: u32 = 1 << 0;

/// Writable flag bit
pub const FLAG_WRITABLE: u32 = 1 << 1;

/// Executable flag bit
pub const FLAG_EXECUTABLE: u32 = 1 << 2;

/// Cacheable flag bit
pub const FLAG_CACHEABLE: u32 = 1 << 3;

/// Shared flag bit
pub const FLAG_SHARED: u32 = 1 << 4;

/// Locked (pinned) flag bit
pub const FLAG_LOCKED: u32 = 1 << 5;

/// Protected flag bit
pub const FLAG_PROTECTED: u32 = 1 << 6;

/// Encrypted flag bit
pub const FLAG_ENCRYPTED: u32 = 1 << 7;

// ============================================================================
// ALIGNMENT
// ============================================================================

/// Default alignment for regions (page-aligned)
pub const DEFAULT_ALIGNMENT: u64 = layout::PAGE_SIZE as u64;

/// Minimum region size
pub const MIN_REGION_SIZE: usize = 1;

// ============================================================================
// HELPER FUNCTIONS
// ============================================================================

/// Aligns a value up to the given alignment.
#[inline]
pub const fn align_up(value: u64, align: u64) -> u64 {
    (value + align - 1) & !(align - 1)
}

/// Aligns a value down to the given alignment.
#[inline]
pub const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

/// Aligns a size up to the given alignment.
#[inline]
pub const fn align_size(size: usize, align: usize) -> usize {
    (size + align - 1) & !(align - 1)
}
