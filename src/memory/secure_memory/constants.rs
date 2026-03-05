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

//! Secure Memory Manager Constants
//!
//! Defines constants for memory region management including:
//! - Region ID generation
//! - Security level thresholds
//! - Memory allocation limits
//! - Statistics tracking

// ============================================================================
// REGION ID GENERATION
// ============================================================================

/// Starting region ID for the first allocated region
pub const INITIAL_REGION_ID: u64 = 1;

/// Maximum number of regions that can be tracked
pub const MAX_REGIONS: usize = 65536;

/// Invalid region ID marker
pub const INVALID_REGION_ID: u64 = 0;

// ============================================================================
// SECURITY LEVELS
// ============================================================================

/// Security level value: Public (lowest security)
pub const SECURITY_LEVEL_PUBLIC: u8 = 0;

/// Security level value: Internal use only
pub const SECURITY_LEVEL_INTERNAL: u8 = 1;

/// Security level value: Confidential
pub const SECURITY_LEVEL_CONFIDENTIAL: u8 = 2;

/// Security level value: Secret
pub const SECURITY_LEVEL_SECRET: u8 = 3;

/// Security level value: Top Secret (highest security)
pub const SECURITY_LEVEL_TOP_SECRET: u8 = 4;

/// Minimum security level that requires encryption
pub const ENCRYPTION_THRESHOLD_LEVEL: u8 = SECURITY_LEVEL_SECRET;

// ============================================================================
// REGION TYPE IDENTIFIERS
// ============================================================================

/// Region type: Executable code
pub const REGION_TYPE_CODE: u8 = 0;

/// Region type: Read/write data
pub const REGION_TYPE_DATA: u8 = 1;

/// Region type: Stack memory
pub const REGION_TYPE_STACK: u8 = 2;

/// Region type: Heap memory
pub const REGION_TYPE_HEAP: u8 = 3;

/// Region type: Device/MMIO memory
pub const REGION_TYPE_DEVICE: u8 = 4;

/// Region type: Secure capsule (isolated memory)
pub const REGION_TYPE_CAPSULE: u8 = 5;

// ============================================================================
// ALLOCATION LIMITS
// ============================================================================

/// Minimum allocation size (1 byte)
pub const MIN_ALLOCATION_SIZE: usize = 1;

/// Maximum allocation size (1 GiB)
pub const MAX_ALLOCATION_SIZE: usize = 1024 * 1024 * 1024;

/// Default alignment for allocations
pub const DEFAULT_ALIGNMENT: usize = 16;

/// Page size for page-aligned allocations
pub const PAGE_SIZE: usize = 4096;

// ============================================================================
// MEMORY ZEROING
// ============================================================================

/// Pattern used to fill secure memory before zeroing (for defense in depth)
pub const SECURE_SCRUB_PATTERN: u8 = 0xAA;

/// Number of scrub passes for high-security deallocations
pub const SECURE_SCRUB_PASSES: usize = 3;

// ============================================================================
// STATISTICS LIMITS
// ============================================================================

/// Maximum tracked allocations (for overflow protection)
pub const MAX_ALLOCATION_COUNT: u64 = u64::MAX - 1;

/// Maximum tracked memory usage
pub const MAX_MEMORY_USAGE: u64 = u64::MAX - 1;

// ============================================================================
// ACCESS CONTROL
// ============================================================================

/// Process ID for kernel-owned regions
pub const KERNEL_PROCESS_ID: u64 = 0;

/// Invalid process ID marker
pub const INVALID_PROCESS_ID: u64 = u64::MAX;

// ============================================================================
// PERMISSION BITS (for region access control)
// ============================================================================

/// Permission: Read access
pub const PERM_READ: u32 = 0x01;

/// Permission: Write access
pub const PERM_WRITE: u32 = 0x02;

/// Permission: Execute access
pub const PERM_EXECUTE: u32 = 0x04;

/// Permission: User-mode accessible
pub const PERM_USER: u32 = 0x08;
