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

//! Page Info Constants
//!
//! Named constants for page metadata management.

/// Page flag bit positions
pub mod flags {
    /// Page is present in memory
    pub const PRESENT_BIT: u32 = 0;
    /// Page is writable
    pub const WRITABLE_BIT: u32 = 1;
    /// Page is accessible from user mode
    pub const USER_BIT: u32 = 2;
    /// Page has been written to
    pub const DIRTY_BIT: u32 = 3;
    /// Page has been accessed
    pub const ACCESSED_BIT: u32 = 4;
    /// Page is locked in memory (cannot be swapped)
    pub const LOCKED_BIT: u32 = 5;
    /// Page contains encrypted data
    pub const ENCRYPTED_BIT: u32 = 6;
}

/// Maximum number of pages that can be tracked
pub const MAX_TRACKED_PAGES: usize = 1_000_000;

/// Initial reference count for newly allocated pages
pub const INITIAL_REF_COUNT: u32 = 1;

/// Page size for calculating page numbers
pub const PAGE_SIZE: u64 = 4096;
