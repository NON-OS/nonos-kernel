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

//! MMIO Constants

// ============================================================================
// ACCESS SIZES
// ============================================================================

/// 8-bit access size
pub const ACCESS_SIZE_8: usize = 1;

/// 16-bit access size
pub const ACCESS_SIZE_16: usize = 2;

/// 32-bit access size
pub const ACCESS_SIZE_32: usize = 4;

/// 64-bit access size
pub const ACCESS_SIZE_64: usize = 8;

// ============================================================================
// VM FLAG BITS (internal representation)
// ============================================================================

/// Present flag bit
pub const VM_FLAG_PRESENT: u32 = 0x01;

/// Writable flag bit
pub const VM_FLAG_WRITABLE: u32 = 0x02;

/// No-execute flag bit (when set)
pub const VM_FLAG_NX: u32 = 0x04;

/// User accessible flag bit
pub const VM_FLAG_USER: u32 = 0x08;

/// Cache disable flag bit
pub const VM_FLAG_CACHE_DISABLE: u32 = 0x10;

/// Write combining flag bit
pub const VM_FLAG_WRITE_COMBINE: u32 = 0x20;

// ============================================================================
// ALIGNMENT HELPERS
// ============================================================================

/// Aligns a value up to the given alignment.
#[inline]
pub const fn align_up(value: usize, align: usize) -> usize {
    if align == 0 || (align & (align - 1)) != 0 {
        return value;
    }
    (value + align - 1) & !(align - 1)
}
