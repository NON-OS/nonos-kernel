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
// REGION ID GENERATION
// ============================================================================
pub const INITIAL_REGION_ID: u64 = 1;
pub const MAX_REGIONS: usize = 65536;
pub const INVALID_REGION_ID: u64 = 0;
// ============================================================================
// SECURITY LEVELS
// ============================================================================
pub const SECURITY_LEVEL_PUBLIC: u8 = 0;
pub const SECURITY_LEVEL_INTERNAL: u8 = 1;
pub const SECURITY_LEVEL_CONFIDENTIAL: u8 = 2;
pub const SECURITY_LEVEL_SECRET: u8 = 3;
pub const SECURITY_LEVEL_TOP_SECRET: u8 = 4;
pub const ENCRYPTION_THRESHOLD_LEVEL: u8 = SECURITY_LEVEL_SECRET;
// ============================================================================
// REGION TYPE IDENTIFIERS
// ============================================================================
pub const REGION_TYPE_CODE: u8 = 0;
pub const REGION_TYPE_DATA: u8 = 1;
pub const REGION_TYPE_STACK: u8 = 2;
pub const REGION_TYPE_HEAP: u8 = 3;
pub const REGION_TYPE_DEVICE: u8 = 4;
pub const REGION_TYPE_CAPSULE: u8 = 5;
// ============================================================================
// ALLOCATION LIMITS
// ============================================================================
pub const MIN_ALLOCATION_SIZE: usize = 1;
pub const MAX_ALLOCATION_SIZE: usize = 1024 * 1024 * 1024;
pub const DEFAULT_ALIGNMENT: usize = 16;
pub const PAGE_SIZE: usize = 4096;
// ============================================================================
// MEMORY ZEROING
// ============================================================================
pub const SECURE_SCRUB_PATTERN: u8 = 0xAA;
pub const SECURE_SCRUB_PASSES: usize = 3;
// ============================================================================
// STATISTICS LIMITS
// ============================================================================
pub const MAX_ALLOCATION_COUNT: u64 = u64::MAX - 1;
pub const MAX_MEMORY_USAGE: u64 = u64::MAX - 1;
// ============================================================================
// ACCESS CONTROL
// ============================================================================
pub const KERNEL_PROCESS_ID: u64 = 0;
pub const INVALID_PROCESS_ID: u64 = u64::MAX;
// ============================================================================
// PERMISSION BITS (for region access control)
// ============================================================================
pub const PERM_READ: u32 = 0x01;
pub const PERM_WRITE: u32 = 0x02;
pub const PERM_EXECUTE: u32 = 0x04;
pub const PERM_USER: u32 = 0x08;
