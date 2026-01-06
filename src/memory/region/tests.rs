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
fn test_flag_bits() {
    assert_eq!(FLAG_READABLE, 1 << 0);
    assert_eq!(FLAG_WRITABLE, 1 << 1);
    assert_eq!(FLAG_EXECUTABLE, 1 << 2);
    assert_eq!(FLAG_CACHEABLE, 1 << 3);
    assert_eq!(FLAG_SHARED, 1 << 4);
    assert_eq!(FLAG_LOCKED, 1 << 5);
    assert_eq!(FLAG_PROTECTED, 1 << 6);
    assert_eq!(FLAG_ENCRYPTED, 1 << 7);
}

// ============================================================================
// HELPER FUNCTION TESTS
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
    assert_eq!(align_down(1, 4096), 0);
    assert_eq!(align_down(4096, 4096), 4096);
    assert_eq!(align_down(8000, 4096), 4096);
}

#[test]
fn test_align_size() {
    assert_eq!(align_size(0, 4096), 0);
    assert_eq!(align_size(1, 4096), 4096);
    assert_eq!(align_size(4096, 4096), 4096);
    assert_eq!(align_size(4097, 4096), 8192);
}

// ============================================================================
// REGION TYPE TESTS
// ============================================================================

#[test]
fn test_region_type_is_allocatable() {
    assert!(RegionType::Available.is_allocatable());
    assert!(!RegionType::Kernel.is_allocatable());
    assert!(!RegionType::Reserved.is_allocatable());
}

#[test]
fn test_region_type_is_kernel() {
    assert!(RegionType::Kernel.is_kernel());
    assert!(RegionType::Stack.is_kernel());
    assert!(RegionType::Heap.is_kernel());
    assert!(!RegionType::User.is_kernel());
}

#[test]
fn test_region_type_is_reserved() {
    assert!(RegionType::Reserved.is_reserved());
    assert!(RegionType::Firmware.is_reserved());
    assert!(RegionType::Bootloader.is_reserved());
    assert!(RegionType::Guard.is_reserved());
    assert!(!RegionType::Kernel.is_reserved());
}

// ============================================================================
// REGION FLAGS TESTS
// ============================================================================

#[test]
fn test_region_flags_bit() {
    assert_eq!(RegionFlags::Readable.bit(), FLAG_READABLE);
    assert_eq!(RegionFlags::Writable.bit(), FLAG_WRITABLE);
    assert_eq!(RegionFlags::Executable.bit(), FLAG_EXECUTABLE);
    assert_eq!(RegionFlags::Cacheable.bit(), FLAG_CACHEABLE);
}

// ============================================================================
// MEM REGION TESTS
// ============================================================================

#[test]
fn test_mem_region_creation() {
    let region = MemRegion::new(0x1000, 0x2000, RegionType::Kernel);
    assert_eq!(region.start, 0x1000);
    assert_eq!(region.size, 0x2000);
    assert_eq!(region.region_type, RegionType::Kernel);
    assert_eq!(region.flags, 0);
}

#[test]
fn test_mem_region_end() {
    let region = MemRegion::new(0x1000, 0x2000, RegionType::Kernel);
    assert_eq!(region.end(), 0x3000);
}

#[test]
fn test_mem_region_contains() {
    let region = MemRegion::new(0x1000, 0x2000, RegionType::Kernel);
    assert!(region.contains(0x1000));
    assert!(region.contains(0x2000));
    assert!(region.contains(0x2FFF));
    assert!(!region.contains(0x0FFF));
    assert!(!region.contains(0x3000));
}

#[test]
fn test_mem_region_contains_range() {
    let outer = MemRegion::new(0x1000, 0x3000, RegionType::Kernel);
    let inner = MemRegion::new(0x2000, 0x1000, RegionType::Kernel);
    let partial = MemRegion::new(0x3000, 0x2000, RegionType::Kernel);

    assert!(outer.contains_range(&inner));
    assert!(!outer.contains_range(&partial));
}

#[test]
fn test_mem_region_overlaps() {
    let r1 = MemRegion::new(0x1000, 0x2000, RegionType::Kernel);
    let r2 = MemRegion::new(0x2000, 0x2000, RegionType::Kernel);
    let r3 = MemRegion::new(0x5000, 0x1000, RegionType::Kernel);

    assert!(r1.overlaps(&r2));
    assert!(r2.overlaps(&r1));
    assert!(!r1.overlaps(&r3));
    assert!(!r3.overlaps(&r1));
}

#[test]
fn test_mem_region_flags() {
    let mut region = MemRegion::new(0x1000, 0x2000, RegionType::Kernel);

    assert!(!region.has_flag(RegionFlags::Readable));

    region.set_flag(RegionFlags::Readable);
    assert!(region.has_flag(RegionFlags::Readable));

    region.set_flag(RegionFlags::Writable);
    assert!(region.has_flag(RegionFlags::Readable));
    assert!(region.has_flag(RegionFlags::Writable));

    region.clear_flag(RegionFlags::Readable);
    assert!(!region.has_flag(RegionFlags::Readable));
    assert!(region.has_flag(RegionFlags::Writable));
}

#[test]
fn test_mem_region_union() {
    let r1 = MemRegion::new(0x1000, 0x1000, RegionType::Available);
    let r2 = MemRegion::new(0x2000, 0x1000, RegionType::Available);

    let union = r1.union(&r2);
    assert!(union.is_some());

    let merged = union.unwrap();
    assert_eq!(merged.start, 0x1000);
    assert_eq!(merged.size, 0x2000);
}

#[test]
fn test_mem_region_union_type_mismatch() {
    let r1 = MemRegion::new(0x1000, 0x1000, RegionType::Available);
    let r2 = MemRegion::new(0x2000, 0x1000, RegionType::Kernel);

    let union = r1.union(&r2);
    assert!(union.is_none());
}

#[test]
fn test_mem_region_subtract() {
    let outer = MemRegion::new(0x1000, 0x4000, RegionType::Available);
    let inner = MemRegion::new(0x2000, 0x1000, RegionType::Available);

    let fragments = outer.subtract(&inner);

    assert!(fragments[0].is_some());
    let left = fragments[0].unwrap();
    assert_eq!(left.start, 0x1000);
    assert_eq!(left.size, 0x1000);

    assert!(fragments[1].is_some());
    let right = fragments[1].unwrap();
    assert_eq!(right.start, 0x3000);
    assert_eq!(right.size, 0x2000);
}

#[test]
fn test_mem_region_subtract_no_overlap() {
    let r1 = MemRegion::new(0x1000, 0x1000, RegionType::Available);
    let r2 = MemRegion::new(0x5000, 0x1000, RegionType::Available);

    let fragments = r1.subtract(&r2);
    assert!(fragments[0].is_some());
    assert!(fragments[1].is_none());

    let unchanged = fragments[0].unwrap();
    assert_eq!(unchanged.start, r1.start);
    assert_eq!(unchanged.size, r1.size);
}

#[test]
fn test_mem_region_page_align() {
    let region = MemRegion::new(0x1100, 0x1100, RegionType::Available);
    let aligned = region.page_align(0x1000);

    assert_eq!(aligned.start, 0x1000);
    assert_eq!(aligned.end(), 0x3000);
}

#[test]
fn test_mem_region_is_valid() {
    let valid = MemRegion::new(0x1000, 0x1000, RegionType::Available);
    assert!(valid.is_valid());

    let zero_size = MemRegion::new(0x1000, 0, RegionType::Available);
    assert!(!zero_size.is_valid());
}

#[test]
fn test_mem_region_is_available() {
    let available = MemRegion::new(0x1000, 0x1000, RegionType::Available);
    assert!(available.is_available());

    let kernel = MemRegion::new(0x1000, 0x1000, RegionType::Kernel);
    assert!(!kernel.is_available());
}

// ============================================================================
// REGION STATS TESTS
// ============================================================================

#[test]
fn test_region_stats_new() {
    let stats = RegionStats::new();
    assert_eq!(stats.total_regions, 0);
    assert_eq!(stats.allocated_bytes, 0);
    assert_eq!(stats.free_bytes, 0);
}

#[test]
fn test_region_stats_total_memory() {
    let stats = RegionStats {
        allocated_bytes: 1000,
        free_bytes: 2000,
        ..RegionStats::new()
    };
    assert_eq!(stats.total_memory(), 3000);
}

#[test]
fn test_region_stats_fragmentation_ratio() {
    let stats = RegionStats {
        free_bytes: 1000,
        largest_free_block: 500,
        ..RegionStats::new()
    };
    let ratio = stats.fragmentation_ratio();
    assert!((ratio - 0.5).abs() < 0.001);

    let no_free = RegionStats::new();
    assert_eq!(no_free.fragmentation_ratio(), 0.0);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_region_error_as_str() {
    assert_eq!(
        RegionError::NotInitialized.as_str(),
        "Region manager not initialized"
    );
    assert_eq!(
        RegionError::Overlapping.as_str(),
        "Region overlaps with existing region"
    );
    assert_eq!(RegionError::NotFound.as_str(), "Region not found");
}

#[test]
fn test_region_error_is_fatal() {
    assert!(RegionError::NotInitialized.is_fatal());
    assert!(RegionError::NoFreeRegion.is_fatal());
    assert!(!RegionError::Overlapping.is_fatal());
}

#[test]
fn test_region_error_is_recoverable() {
    assert!(RegionError::Overlapping.is_recoverable());
    assert!(RegionError::NotFound.is_recoverable());
    assert!(RegionError::InvalidSplitOffset.is_recoverable());
    assert!(!RegionError::NoFreeRegion.is_recoverable());
}

#[test]
fn test_region_error_display() {
    let error = RegionError::NotFound;
    let msg = format!("{}", error);
    assert_eq!(msg, "Region not found");
}

#[test]
fn test_region_error_from_str() {
    assert_eq!(
        RegionError::from("Region manager not initialized"),
        RegionError::NotInitialized
    );
    assert_eq!(
        RegionError::from("Region overlaps with existing region"),
        RegionError::Overlapping
    );
    assert_eq!(RegionError::from("Region not found"), RegionError::NotFound);
}
