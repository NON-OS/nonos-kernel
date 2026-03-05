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

//! Boot Memory Manager Constants
//!
//! Defines constants for early boot memory management including:
//! - Boot handoff magic and version numbers
//! - Default memory region definitions
//! - Hardware MMIO region addresses
//! - Page sizes and alignment

// ============================================================================
// BOOT HANDOFF PROTOCOL
// ============================================================================

/// Magic value for NONOS boot handoff structure ("NONOSOŚ\0")
pub const BOOT_HANDOFF_MAGIC: u64 = 0x4E4F4E4F534F5300;

/// Current boot handoff protocol version
pub const BOOT_HANDOFF_VERSION: u16 = 1;

/// Minimum supported handoff version
pub const MIN_HANDOFF_VERSION: u16 = 1;

/// Maximum supported handoff version
pub const MAX_HANDOFF_VERSION: u16 = 1;

// ============================================================================
// DEFAULT MEMORY REGIONS
// ============================================================================

/// Start of conventional memory (0 to 1 MiB is reserved)
pub const CONVENTIONAL_MEMORY_START: u64 = 0x0;

/// End of conventional memory (1 MiB boundary)
pub const CONVENTIONAL_MEMORY_END: u64 = 0x100000;

/// Default kernel region start (1 MiB)
pub const DEFAULT_KERNEL_START: u64 = 0x100000;

/// Default kernel region end (4 MiB)
pub const DEFAULT_KERNEL_END: u64 = 0x400000;

/// Default available memory start (4 MiB)
pub const DEFAULT_AVAILABLE_START: u64 = 0x400000;

/// Default available memory end (128 MiB)
pub const DEFAULT_AVAILABLE_END: u64 = 0x8000000;

// ============================================================================
// HARDWARE MMIO REGIONS
// ============================================================================

/// VGA text mode buffer start
pub const VGA_TEXT_START: u64 = 0xB8000;

/// VGA text mode buffer end
pub const VGA_TEXT_END: u64 = 0xC0000;

/// Legacy video memory start
pub const LEGACY_VIDEO_START: u64 = 0xA0000;

/// Legacy video memory end
pub const LEGACY_VIDEO_END: u64 = 0x100000;

/// PCI configuration space start (3 GiB)
pub const PCI_CONFIG_START: u64 = 0xC0000000;

/// PCI configuration space end (4 GiB)
pub const PCI_CONFIG_END: u64 = 0x100000000;

/// I/O APIC base address
pub const IOAPIC_BASE: u64 = 0xFEC00000;

/// I/O APIC region size (4 KiB)
pub const IOAPIC_SIZE: u64 = 0x1000;

/// Local APIC base address
pub const LAPIC_BASE: u64 = 0xFEE00000;

/// Local APIC region size (4 KiB)
pub const LAPIC_SIZE: u64 = 0x1000;

// ============================================================================
// PAGE SIZES AND ALIGNMENT
// ============================================================================

/// Standard page size (4 KiB)
pub const PAGE_SIZE: usize = 4096;

/// Page size as u64 for address calculations
pub const PAGE_SIZE_U64: u64 = PAGE_SIZE as u64;

/// Minimum allocation alignment
pub const MIN_ALIGNMENT: usize = 8;

/// Maximum alignment (1 GiB, for huge page support)
pub const MAX_ALIGNMENT: usize = 1024 * 1024 * 1024;

// ============================================================================
// REGION TYPE IDENTIFIERS
// ============================================================================

/// Region type: Available for allocation
pub const REGION_TYPE_AVAILABLE: u8 = 0;

/// Region type: Reserved by firmware/hardware
pub const REGION_TYPE_RESERVED: u8 = 1;

/// Region type: Kernel code/data
pub const REGION_TYPE_KERNEL: u8 = 2;

/// Region type: Secure capsule
pub const REGION_TYPE_CAPSULE: u8 = 3;

/// Region type: Hardware MMIO
pub const REGION_TYPE_HARDWARE: u8 = 4;

/// Region type: Defective memory
pub const REGION_TYPE_DEFECTIVE: u8 = 5;

// ============================================================================
// REGION FLAGS
// ============================================================================

/// Flag: Region is read-only
pub const REGION_FLAG_READONLY: u32 = 0x0001;

/// Flag: Region is non-cacheable
pub const REGION_FLAG_UNCACHED: u32 = 0x0002;

/// Flag: Region is write-through cached
pub const REGION_FLAG_WRITE_THROUGH: u32 = 0x0004;

/// Flag: Region is write-combining
pub const REGION_FLAG_WRITE_COMBINE: u32 = 0x0008;

/// Flag: Region contains firmware tables
pub const REGION_FLAG_FIRMWARE: u32 = 0x0010;

/// Flag: Region is reclaimable after boot
pub const REGION_FLAG_RECLAIMABLE: u32 = 0x0020;

// ============================================================================
// ALLOCATION LIMITS
// ============================================================================

/// Maximum number of boot memory regions
pub const MAX_BOOT_REGIONS: usize = 256;

/// Minimum region size worth tracking (4 KiB)
pub const MIN_REGION_SIZE: u64 = PAGE_SIZE_U64;

/// Maximum single allocation size (256 MiB)
pub const MAX_ALLOCATION_SIZE: usize = 256 * 1024 * 1024;

// ============================================================================
// ENTROPY
// ============================================================================

/// Size of boot entropy buffer
pub const BOOT_ENTROPY_SIZE: usize = 32;
