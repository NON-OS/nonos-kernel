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

// ============================================================================
// CONSTANT TESTS
// ============================================================================

#[test]
fn test_access_sizes() {
    assert_eq!(ACCESS_SIZE_8, 1);
    assert_eq!(ACCESS_SIZE_16, 2);
    assert_eq!(ACCESS_SIZE_32, 4);
    assert_eq!(ACCESS_SIZE_64, 8);
}

#[test]
fn test_vm_flag_bits() {
    assert_eq!(VM_FLAG_PRESENT, 0x01);
    assert_eq!(VM_FLAG_WRITABLE, 0x02);
    assert_eq!(VM_FLAG_NX, 0x04);
    assert_eq!(VM_FLAG_USER, 0x08);
    assert_eq!(VM_FLAG_CACHE_DISABLE, 0x10);
    assert_eq!(VM_FLAG_WRITE_COMBINE, 0x20);
}

#[test]
fn test_align_up() {
    assert_eq!(align_up(0, 4096), 0);
    assert_eq!(align_up(1, 4096), 4096);
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(4097, 4096), 8192);
    assert_eq!(align_up(8191, 4096), 8192);
}

#[test]
fn test_align_up_invalid() {
    // Zero alignment returns value unchanged
    assert_eq!(align_up(100, 0), 100);
    // Non-power-of-two returns value unchanged
    assert_eq!(align_up(100, 3), 100);
}

// ============================================================================
// MMIO FLAGS TESTS
// ============================================================================

#[test]
fn test_mmio_flags_device() {
    let flags = MmioFlags::device();
    assert!(!flags.cacheable);
    assert!(!flags.write_combining);
    assert!(!flags.user_accessible);
    assert!(!flags.executable);
}

#[test]
fn test_mmio_flags_framebuffer() {
    let flags = MmioFlags::framebuffer();
    assert!(!flags.cacheable);
    assert!(flags.write_combining);
    assert!(!flags.user_accessible);
    assert!(!flags.executable);
}

#[test]
fn test_mmio_flags_user_device() {
    let flags = MmioFlags::user_device();
    assert!(!flags.cacheable);
    assert!(!flags.write_combining);
    assert!(flags.user_accessible);
    assert!(!flags.executable);
}

#[test]
fn test_mmio_flags_default() {
    let flags = MmioFlags::default();
    assert_eq!(flags, MmioFlags::device());
}

#[test]
fn test_mmio_flags_to_vm_flags() {
    let device = MmioFlags::device();
    let vm_flags = device.to_vm_flags();
    assert!(vm_flags & VM_FLAG_PRESENT != 0);
    assert!(vm_flags & VM_FLAG_WRITABLE != 0);
    assert!(vm_flags & VM_FLAG_NX != 0); // Not executable
    assert!(vm_flags & VM_FLAG_CACHE_DISABLE != 0);
    assert!(vm_flags & VM_FLAG_USER == 0);

    let framebuffer = MmioFlags::framebuffer();
    let vm_flags = framebuffer.to_vm_flags();
    assert!(vm_flags & VM_FLAG_WRITE_COMBINE != 0);
}

// ============================================================================
// MMIO REGION TESTS
// ============================================================================

#[test]
fn test_mmio_region_creation() {
    use x86_64::{PhysAddr, VirtAddr};

    let region = MmioRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        MmioFlags::device(),
        1,
    );

    assert_eq!(region.va.as_u64(), 0x1000);
    assert_eq!(region.pa.as_u64(), 0x2000);
    assert_eq!(region.size, 4096);
    assert_eq!(region.region_id, 1);
}

#[test]
fn test_mmio_region_end_va() {
    use x86_64::{PhysAddr, VirtAddr};

    let region = MmioRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        8192,
        MmioFlags::device(),
        1,
    );

    assert_eq!(region.end_va().as_u64(), 0x3000);
}

#[test]
fn test_mmio_region_contains() {
    use x86_64::{PhysAddr, VirtAddr};

    let region = MmioRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        MmioFlags::device(),
        1,
    );

    assert!(region.contains(VirtAddr::new(0x1000)));
    assert!(region.contains(VirtAddr::new(0x1500)));
    assert!(region.contains(VirtAddr::new(0x1FFF)));
    assert!(!region.contains(VirtAddr::new(0x2000)));
    assert!(!region.contains(VirtAddr::new(0x0FFF)));
}

#[test]
fn test_mmio_region_validate_access() {
    use x86_64::{PhysAddr, VirtAddr};

    let region = MmioRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        MmioFlags::device(),
        1,
    );

    assert!(region.validate_access(0, 4));
    assert!(region.validate_access(100, 4));
    assert!(region.validate_access(4092, 4));
    assert!(!region.validate_access(4093, 4)); // Would overflow
    assert!(!region.validate_access(4096, 1)); // At end
}

#[test]
fn test_mmio_region_offset_addr() {
    use x86_64::{PhysAddr, VirtAddr};

    let region = MmioRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        MmioFlags::device(),
        1,
    );

    assert_eq!(
        region.offset_addr(0),
        Some(VirtAddr::new(0x1000))
    );
    assert_eq!(
        region.offset_addr(100),
        Some(VirtAddr::new(0x1064))
    );
    assert_eq!(region.offset_addr(4096), None);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_mmio_error_as_str() {
    assert_eq!(
        MmioError::NotInitialized.as_str(),
        "MMIO manager not initialized"
    );
    assert_eq!(MmioError::InvalidSize.as_str(), "Invalid size");
    assert_eq!(
        MmioError::AddressSpaceExhausted.as_str(),
        "MMIO virtual address space exhausted"
    );
}

#[test]
fn test_mmio_error_is_fatal() {
    assert!(MmioError::AddressSpaceExhausted.is_fatal());
    assert!(MmioError::MappingFailed.is_fatal());
    assert!(MmioError::UnmapFailed.is_fatal());
    assert!(!MmioError::InvalidSize.is_fatal());
    assert!(!MmioError::RegionNotFound.is_fatal());
}

#[test]
fn test_mmio_error_display() {
    let error = MmioError::NotPageAligned;
    let msg = format!("{}", error);
    assert_eq!(msg, "Physical address not page aligned");
}

#[test]
fn test_mmio_error_from_str() {
    assert_eq!(
        MmioError::from("MMIO manager not initialized"),
        MmioError::NotInitialized
    );
    assert_eq!(
        MmioError::from("MMIO region not found"),
        MmioError::RegionNotFound
    );
}

// ============================================================================
// STATS TESTS
// ============================================================================

#[test]
fn test_mmio_stats_new() {
    let stats = MmioStats::new();
    assert_eq!(stats.total_regions(), 0);
    assert_eq!(stats.total_mapped_size(), 0);
    assert_eq!(stats.read_operations(), 0);
    assert_eq!(stats.write_operations(), 0);
}

#[test]
fn test_mmio_stats_next_id() {
    let stats = MmioStats::new();
    let id1 = stats.next_id();
    let id2 = stats.next_id();
    assert_eq!(id2, id1 + 1);
}

#[test]
fn test_mmio_stats_record_mapping() {
    let stats = MmioStats::new();
    stats.record_mapping(4096);
    assert_eq!(stats.total_regions(), 1);
    assert_eq!(stats.total_mapped_size(), 4096);

    stats.record_mapping(8192);
    assert_eq!(stats.total_regions(), 2);
    assert_eq!(stats.total_mapped_size(), 4096 + 8192);
}

#[test]
fn test_mmio_stats_record_unmapping() {
    let stats = MmioStats::new();
    stats.record_mapping(4096);
    stats.record_mapping(8192);
    stats.record_unmapping(4096);

    assert_eq!(stats.total_regions(), 1);
    assert_eq!(stats.total_mapped_size(), 8192);
}

#[test]
fn test_mmio_stats_record_io() {
    let stats = MmioStats::new();
    stats.record_read();
    stats.record_read();
    stats.record_write();

    assert_eq!(stats.read_operations(), 2);
    assert_eq!(stats.write_operations(), 1);
}

#[test]
fn test_mmio_stats_snapshot() {
    let stats = MmioStats::new();
    stats.record_mapping(4096);
    stats.record_read();
    stats.record_write();

    let snapshot = stats.snapshot();
    assert_eq!(snapshot.total_regions, 1);
    assert_eq!(snapshot.total_mapped_size, 4096);
    assert_eq!(snapshot.read_operations, 1);
    assert_eq!(snapshot.write_operations, 1);
}

// ============================================================================
// STATS SNAPSHOT TESTS
// ============================================================================

#[test]
fn test_mmio_stats_snapshot_new() {
    let snapshot = MmioStatsSnapshot::new();
    assert_eq!(snapshot.total_regions, 0);
    assert_eq!(snapshot.total_operations(), 0);
}

#[test]
fn test_mmio_stats_snapshot_total_operations() {
    let snapshot = MmioStatsSnapshot {
        total_regions: 1,
        total_mapped_size: 4096,
        read_operations: 100,
        write_operations: 50,
    };
    assert_eq!(snapshot.total_operations(), 150);
}

// ============================================================================
// MANAGER TESTS
// ============================================================================

#[test]
fn test_manager_new() {
    let manager = MmioManager::new();
    assert!(!manager.is_initialized());
}

#[test]
fn test_manager_init() {
    let mut manager = MmioManager::new();
    assert!(manager.init().is_ok());
    assert!(manager.is_initialized());
    assert!(manager.init().is_ok());
}
