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

use super::*;
use super::constants::*;
use super::error::BootMemoryError;

// ============================================================================
// CONSTANTS TESTS
// ============================================================================

#[test]
fn test_boot_handoff_magic() {
    assert_eq!(BOOT_HANDOFF_MAGIC, 0x4E4F4E4F534F5300);
}

#[test]
fn test_handoff_version() {
    assert_eq!(BOOT_HANDOFF_VERSION, 1);
    assert_eq!(MIN_HANDOFF_VERSION, 1);
    assert_eq!(MAX_HANDOFF_VERSION, 1);
}

#[test]
fn test_conventional_memory() {
    assert_eq!(CONVENTIONAL_MEMORY_START, 0);
    assert_eq!(CONVENTIONAL_MEMORY_END, 0x100000); // 1 MiB
}

#[test]
fn test_default_kernel_region() {
    assert_eq!(DEFAULT_KERNEL_START, 0x100000); // 1 MiB
    assert_eq!(DEFAULT_KERNEL_END, 0x400000);   // 4 MiB
}

#[test]
fn test_default_available_region() {
    assert_eq!(DEFAULT_AVAILABLE_START, 0x400000); // 4 MiB
    assert_eq!(DEFAULT_AVAILABLE_END, 0x8000000);  // 128 MiB
}

#[test]
fn test_hardware_region_constants() {
    assert_eq!(VGA_TEXT_START, 0xB8000);
    assert_eq!(VGA_TEXT_END, 0xC0000);
    assert_eq!(IOAPIC_BASE, 0xFEC00000);
    assert_eq!(LAPIC_BASE, 0xFEE00000);
}

#[test]
fn test_page_size_constant() {
    assert_eq!(PAGE_SIZE, 4096);
    assert_eq!(PAGE_SIZE_U64, 4096);
}

#[test]
fn test_alignment_constants() {
    assert_eq!(MIN_ALIGNMENT, 8);
    assert_eq!(MAX_ALIGNMENT, 1024 * 1024 * 1024);
}

#[test]
fn test_region_type_values() {
    assert_eq!(REGION_TYPE_AVAILABLE, 0);
    assert_eq!(REGION_TYPE_RESERVED, 1);
    assert_eq!(REGION_TYPE_KERNEL, 2);
    assert_eq!(REGION_TYPE_CAPSULE, 3);
    assert_eq!(REGION_TYPE_HARDWARE, 4);
    assert_eq!(REGION_TYPE_DEFECTIVE, 5);
}

#[test]
fn test_region_flags() {
    assert_eq!(REGION_FLAG_READONLY, 0x0001);
    assert_eq!(REGION_FLAG_UNCACHED, 0x0002);
    assert_eq!(REGION_FLAG_WRITE_THROUGH, 0x0004);
    assert_eq!(REGION_FLAG_WRITE_COMBINE, 0x0008);
    assert_eq!(REGION_FLAG_FIRMWARE, 0x0010);
    assert_eq!(REGION_FLAG_RECLAIMABLE, 0x0020);
}

#[test]
fn test_allocation_limits() {
    assert_eq!(MAX_BOOT_REGIONS, 256);
    assert_eq!(MIN_REGION_SIZE, PAGE_SIZE_U64);
    assert_eq!(MAX_ALLOCATION_SIZE, 256 * 1024 * 1024);
}

#[test]
fn test_entropy_size() {
    assert_eq!(BOOT_ENTROPY_SIZE, 32);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_error_display() {
    assert_eq!(BootMemoryError::NotInitialized.as_str(), "Boot memory manager not initialized");
    assert_eq!(BootMemoryError::AlreadyInitialized.as_str(), "Boot memory manager already initialized");
    assert_eq!(BootMemoryError::OutOfMemory.as_str(), "Out of memory");
}

#[test]
fn test_error_is_fatal() {
    assert!(BootMemoryError::NoRegionsDefined.is_fatal());
    assert!(BootMemoryError::NoAvailableMemory.is_fatal());
    assert!(BootMemoryError::OutOfMemory.is_fatal());
    assert!(BootMemoryError::OverlappingRegions.is_fatal());

    assert!(!BootMemoryError::NotInitialized.is_fatal());
    assert!(!BootMemoryError::InvalidHandoffMagic.is_fatal());
}

#[test]
fn test_error_can_use_defaults() {
    assert!(BootMemoryError::InvalidHandoffMagic.can_use_defaults());
    assert!(BootMemoryError::UnsupportedVersion.can_use_defaults());
    assert!(BootMemoryError::InvalidHandoffPointer.can_use_defaults());
    assert!(BootMemoryError::MemoryMapParseError.can_use_defaults());

    assert!(!BootMemoryError::OutOfMemory.can_use_defaults());
    assert!(!BootMemoryError::NoRegionsDefined.can_use_defaults());
}

#[test]
fn test_error_from_string() {
    let err: BootMemoryError = "Boot memory not initialized".into();
    assert_eq!(err, BootMemoryError::NotInitialized);

    let err: BootMemoryError = "Out of memory".into();
    assert_eq!(err, BootMemoryError::OutOfMemory);
}

// ============================================================================
// REGION TYPE TESTS
// ============================================================================

#[test]
fn test_region_type_as_u8() {
    assert_eq!(RegionType::Available.as_u8(), REGION_TYPE_AVAILABLE);
    assert_eq!(RegionType::Reserved.as_u8(), REGION_TYPE_RESERVED);
    assert_eq!(RegionType::Kernel.as_u8(), REGION_TYPE_KERNEL);
    assert_eq!(RegionType::Capsule.as_u8(), REGION_TYPE_CAPSULE);
    assert_eq!(RegionType::Hardware.as_u8(), REGION_TYPE_HARDWARE);
    assert_eq!(RegionType::Defective.as_u8(), REGION_TYPE_DEFECTIVE);
}

#[test]
fn test_region_type_as_str() {
    assert_eq!(RegionType::Available.as_str(), "Available");
    assert_eq!(RegionType::Reserved.as_str(), "Reserved");
    assert_eq!(RegionType::Kernel.as_str(), "Kernel");
    assert_eq!(RegionType::Capsule.as_str(), "Capsule");
    assert_eq!(RegionType::Hardware.as_str(), "Hardware");
    assert_eq!(RegionType::Defective.as_str(), "Defective");
}

#[test]
fn test_region_type_is_allocatable() {
    assert!(RegionType::Available.is_allocatable());
    assert!(!RegionType::Reserved.is_allocatable());
    assert!(!RegionType::Kernel.is_allocatable());
    assert!(!RegionType::Capsule.is_allocatable());
    assert!(!RegionType::Hardware.is_allocatable());
    assert!(!RegionType::Defective.is_allocatable());
}

// ============================================================================
// MEMORY REGION TESTS
// ============================================================================

#[test]
fn test_memory_region_new() {
    let region = MemoryRegion::new(0x1000, 0x2000, RegionType::Available, 0);
    assert_eq!(region.start.as_u64(), 0x1000);
    assert_eq!(region.end.as_u64(), 0x2000);
    assert_eq!(region.region_type, RegionType::Available);
    assert_eq!(region.flags, 0);
}

#[test]
fn test_memory_region_size() {
    let region = MemoryRegion::new(0x1000, 0x3000, RegionType::Available, 0);
    assert_eq!(region.size(), 0x2000);

    let empty = MemoryRegion::new(0x1000, 0x1000, RegionType::Available, 0);
    assert_eq!(empty.size(), 0);
}

#[test]
fn test_memory_region_page_count() {
    let region = MemoryRegion::new(0, PAGE_SIZE_U64 * 10, RegionType::Available, 0);
    assert_eq!(region.page_count(), 10);
}

#[test]
fn test_memory_region_contains() {
    let region = MemoryRegion::new(0x1000, 0x3000, RegionType::Available, 0);

    assert!(region.contains(PhysAddr::new(0x1000)));
    assert!(region.contains(PhysAddr::new(0x2000)));
    assert!(region.contains(PhysAddr::new(0x2FFF)));

    assert!(!region.contains(PhysAddr::new(0x0FFF)));
    assert!(!region.contains(PhysAddr::new(0x3000)));
}

#[test]
fn test_memory_region_is_available() {
    let available = MemoryRegion::new(0, 0x1000, RegionType::Available, 0);
    assert!(available.is_available());

    let reserved = MemoryRegion::new(0, 0x1000, RegionType::Reserved, 0);
    assert!(!reserved.is_available());
}

#[test]
fn test_memory_region_is_empty() {
    let empty = MemoryRegion::new(0x1000, 0x1000, RegionType::Available, 0);
    assert!(empty.is_empty());

    let valid = MemoryRegion::new(0x1000, 0x2000, RegionType::Available, 0);
    assert!(!valid.is_empty());
}

#[test]
fn test_memory_region_has_flag() {
    let region = MemoryRegion::new(0, 0x1000, RegionType::Hardware, REGION_FLAG_UNCACHED);
    assert!(region.has_flag(REGION_FLAG_UNCACHED));
    assert!(!region.has_flag(REGION_FLAG_READONLY));

    let multi_flag = MemoryRegion::new(
        0,
        0x1000,
        RegionType::Hardware,
        REGION_FLAG_UNCACHED | REGION_FLAG_READONLY,
    );
    assert!(multi_flag.has_flag(REGION_FLAG_UNCACHED));
    assert!(multi_flag.has_flag(REGION_FLAG_READONLY));
}

// ============================================================================
// REGION STATS TESTS
// ============================================================================

#[test]
fn test_region_stats_default() {
    let stats = RegionStats::default();
    assert_eq!(stats.total_memory, 0);
    assert_eq!(stats.available_memory, 0);
    assert_eq!(stats.allocated_memory, 0);
    assert_eq!(stats.region_count, 0);
}

#[test]
fn test_region_stats_free_memory() {
    let stats = RegionStats {
        available_memory: 1000,
        allocated_memory: 300,
        ..Default::default()
    };
    assert_eq!(stats.free_memory(), 700);

    let over_allocated = RegionStats {
        available_memory: 100,
        allocated_memory: 200,
        ..Default::default()
    };
    assert_eq!(over_allocated.free_memory(), 0);
}

#[test]
fn test_region_stats_allocation_percent() {
    let stats = RegionStats {
        available_memory: 1000,
        allocated_memory: 250,
        ..Default::default()
    };
    assert!((stats.allocation_percent() - 25.0).abs() < 0.01);

    let empty = RegionStats::default();
    assert_eq!(empty.allocation_percent(), 0.0);
}

// ============================================================================
// ALIGNMENT UTILITY TESTS
// ============================================================================

#[test]
fn test_align_up() {
    assert_eq!(align_up(0, 4096), 0);
    assert_eq!(align_up(1, 4096), 4096);
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(4097, 4096), 8192);
}

#[test]
fn test_align_down() {
    assert_eq!(align_down(0, 4096), 0);
    assert_eq!(align_down(4095, 4096), 0);
    assert_eq!(align_down(4096, 4096), 4096);
    assert_eq!(align_down(8191, 4096), 4096);
}

#[test]
fn test_align_up_invalid_alignment() {
    // Zero alignment
    assert_eq!(align_up(1234, 0), 1234);
    // Non-power-of-two
    assert_eq!(align_up(1234, 3), 1234);
}

#[test]
fn test_align_down_invalid_alignment() {
    assert_eq!(align_down(1234, 0), 1234);
    assert_eq!(align_down(1234, 5), 1234);
}

// ============================================================================
// BOOT HANDOFF TESTS
// ============================================================================

#[test]
fn test_boot_handoff_validate_valid() {
    let handoff = BootHandoff {
        magic: BOOT_HANDOFF_MAGIC,
        version: BOOT_HANDOFF_VERSION,
        flags: 0,
        memory_base: 0x100000,
        memory_size: 0x1000000,
        kernel_base: 0x100000,
        kernel_size: 0x100000,
        capsule_base: 0,
        capsule_size: 0,
        entropy: [0; BOOT_ENTROPY_SIZE],
        timestamp: 0,
    };

    assert!(handoff.validate().is_ok());
}

#[test]
fn test_boot_handoff_validate_invalid_magic() {
    let handoff = BootHandoff {
        magic: 0x12345678,
        version: BOOT_HANDOFF_VERSION,
        flags: 0,
        memory_base: 0,
        memory_size: 0,
        kernel_base: 0,
        kernel_size: 0,
        capsule_base: 0,
        capsule_size: 0,
        entropy: [0; BOOT_ENTROPY_SIZE],
        timestamp: 0,
    };

    assert_eq!(handoff.validate(), Err(BootMemoryError::InvalidHandoffMagic));
}

#[test]
fn test_boot_handoff_validate_invalid_version() {
    let handoff = BootHandoff {
        magic: BOOT_HANDOFF_MAGIC,
        version: 99,
        flags: 0,
        memory_base: 0,
        memory_size: 0,
        kernel_base: 0,
        kernel_size: 0,
        capsule_base: 0,
        capsule_size: 0,
        entropy: [0; BOOT_ENTROPY_SIZE],
        timestamp: 0,
    };

    assert_eq!(handoff.validate(), Err(BootMemoryError::UnsupportedVersion));
}

#[test]
fn test_boot_handoff_has_capsule() {
    let with_capsule = BootHandoff {
        magic: BOOT_HANDOFF_MAGIC,
        version: BOOT_HANDOFF_VERSION,
        flags: 0,
        memory_base: 0,
        memory_size: 0,
        kernel_base: 0,
        kernel_size: 0,
        capsule_base: 0x1000000,
        capsule_size: 0x10000,
        entropy: [0; BOOT_ENTROPY_SIZE],
        timestamp: 0,
    };
    assert!(with_capsule.has_capsule());

    let without_capsule = BootHandoff {
        magic: BOOT_HANDOFF_MAGIC,
        version: BOOT_HANDOFF_VERSION,
        flags: 0,
        memory_base: 0,
        memory_size: 0,
        kernel_base: 0,
        kernel_size: 0,
        capsule_base: 0,
        capsule_size: 0,
        entropy: [0; BOOT_ENTROPY_SIZE],
        timestamp: 0,
    };
    assert!(!without_capsule.has_capsule());
}

// ============================================================================
// PUBLIC API TESTS
// ============================================================================

#[test]
fn test_total_memory_initial() {
    // Just verify it doesn't panic
    let _ = total_memory();
}

#[test]
fn test_available_memory_initial() {
    let _ = available_memory();
}

#[test]
fn test_allocation_count_initial() {
    let _ = allocation_count();
}

#[test]
fn test_is_initialized() {
    let _ = is_initialized();
}
