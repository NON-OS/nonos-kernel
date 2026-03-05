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

//! Frame Allocator Constants
//!
//! All named constants for the frame allocator module.
//! Replaces magic numbers for maintainability and clarity.

/// Size of a single physical page frame in bytes (4 KiB)
pub const FRAME_SIZE: u64 = 4096;

/// Size of a single physical page frame as usize
pub const FRAME_SIZE_USIZE: usize = 4096;

/// Default start address for fallback memory region (16 MiB)
/// This is above the conventional memory and legacy device regions
pub const DEFAULT_REGION_START: u64 = 16 * 1024 * 1024;

/// Default end address for fallback memory region (512 MiB)
/// Conservative upper bound for systems with limited memory
pub const DEFAULT_REGION_END: u64 = 512 * 1024 * 1024;

/// Alignment requirement for frame addresses (must be page-aligned)
pub const FRAME_ALIGNMENT: u64 = FRAME_SIZE;

/// Minimum valid physical address for allocation
pub const MIN_ALLOC_ADDRESS: u64 = 0x100000; // 1 MiB (above conventional memory)

/// Maximum number of memory regions that can be tracked
pub const MAX_MEMORY_REGIONS: usize = 64;
