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

//! Page Allocator Constants
//!
//! Named constants for page-level allocation operations.

/// Initial page ID for allocations
pub const INITIAL_PAGE_ID: u64 = 1;

/// Maximum number of pages that can be tracked
pub const MAX_TRACKED_PAGES: usize = 100_000;

/// Zero byte pattern for clearing memory
pub const ZERO_PATTERN: u8 = 0;

/// Maximum allocation size in bytes (1 GiB)
pub const MAX_ALLOCATION_SIZE: usize = 1024 * 1024 * 1024;

/// Minimum allocation size (one page)
pub const MIN_ALLOCATION_SIZE: usize = 4096;
