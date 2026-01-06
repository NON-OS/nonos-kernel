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
//
//! Boot Memory Manager Constants
// ============================================================================
// BOOT HANDOFF PROTOCOL
// ============================================================================
pub const BOOT_HANDOFF_MAGIC: u64 = 0x4E4F4E4F534F5300;
pub const BOOT_HANDOFF_VERSION: u16 = 1;
pub const MIN_HANDOFF_VERSION: u16 = 1;
pub const MAX_HANDOFF_VERSION: u16 = 1;
// ============================================================================
// DEFAULT MEMORY REGIONS
// ============================================================================
pub const CONVENTIONAL_MEMORY_START: u64 = 0x0;
pub const CONVENTIONAL_MEMORY_END: u64 = 0x100000;
pub const DEFAULT_KERNEL_START: u64 = 0x100000;
pub const DEFAULT_KERNEL_END: u64 = 0x400000;
pub const DEFAULT_AVAILABLE_START: u64 = 0x400000;
pub const DEFAULT_AVAILABLE_END: u64 = 0x8000000;
// ============================================================================
// HARDWARE MMIO REGIONS
// ============================================================================
pub const VGA_TEXT_START: u64 = 0xB8000;
pub const VGA_TEXT_END: u64 = 0xC0000;
pub const LEGACY_VIDEO_START: u64 = 0xA0000;
pub const LEGACY_VIDEO_END: u64 = 0x100000;
pub const PCI_CONFIG_START: u64 = 0xC0000000;
pub const PCI_CONFIG_END: u64 = 0x100000000;
pub const IOAPIC_BASE: u64 = 0xFEC00000;
pub const IOAPIC_SIZE: u64 = 0x1000;
pub const LAPIC_BASE: u64 = 0xFEE00000;
pub const LAPIC_SIZE: u64 = 0x1000;
// ============================================================================
// PAGE SIZES AND ALIGNMENT
// ============================================================================
pub const PAGE_SIZE: usize = 4096;
pub const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;
pub const MIN_ALIGNMENT: usize = 8;
pub const MAX_ALIGNMENT: usize = 1024 * 1024 * 1024;
// ============================================================================
// REGION TYPE IDENTIFIERS
// ============================================================================
pub const REGION_TYPE_AVAILABLE: u8 = 0;
pub const REGION_TYPE_RESERVED: u8 = 1;
pub const REGION_TYPE_KERNEL: u8 = 2;
pub const REGION_TYPE_CAPSULE: u8 = 3;
pub const REGION_TYPE_HARDWARE: u8 = 4;
pub const REGION_TYPE_DEFECTIVE: u8 = 5;
// ============================================================================
// REGION FLAGS
// ============================================================================
pub const REGION_FLAG_READONLY: u32 = 0x0001;
pub const REGION_FLAG_UNCACHED: u32 = 0x0002;
pub const REGION_FLAG_WRITE_THROUGH: u32 = 0x0004;
pub const REGION_FLAG_WRITE_COMBINE: u32 = 0x0008;
pub const REGION_FLAG_FIRMWARE: u32 = 0x0010;
pub const REGION_FLAG_RECLAIMABLE: u32 = 0x0020;
// ============================================================================
// ALLOCATION LIMITS
// ============================================================================
pub const MAX_BOOT_REGIONS: usize = 256;
pub const MIN_REGION_SIZE: u64 = PAGE_SIZE_U64;
pub const MAX_ALLOCATION_SIZE: usize = 256 * 1024 * 1024;
// ============================================================================
// ENTROPY
// ============================================================================
pub const BOOT_ENTROPY_SIZE: usize = 32;
