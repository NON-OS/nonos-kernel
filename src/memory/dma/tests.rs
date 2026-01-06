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
fn test_alignment_constants() {
    assert_eq!(DEFAULT_ALIGNMENT, 4096);
    assert_eq!(DEFAULT_MAX_SEGMENT_SIZE, 1024 * 1024);
}

#[test]
fn test_dma32_limit() {
    assert_eq!(DMA32_LIMIT, 0x1_0000_0000);
}

#[test]
fn test_size_limits() {
    assert_eq!(MIN_DMA_SIZE, 1);
    assert_eq!(MAX_DMA_SIZE, 256 * 1024 * 1024);
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
fn test_is_aligned() {
    assert!(is_aligned(0, 4096));
    assert!(is_aligned(4096, 4096));
    assert!(is_aligned(8192, 4096));
    assert!(!is_aligned(1, 4096));
    assert!(!is_aligned(4097, 4096));
}

#[test]
fn test_pages_needed() {
    assert_eq!(pages_needed(0), 0);
    assert_eq!(pages_needed(1), 1);
    assert_eq!(pages_needed(4096), 1);
    assert_eq!(pages_needed(4097), 2);
    assert_eq!(pages_needed(8192), 2);
}

#[test]
fn test_is_dma32_compatible() {
    assert!(is_dma32_compatible(0));
    assert!(is_dma32_compatible(0x1000));
    assert!(is_dma32_compatible(0xFFFF_FFFF));
    assert!(!is_dma32_compatible(0x1_0000_0000));
    assert!(!is_dma32_compatible(0x2_0000_0000));
}

#[test]
fn test_is_range_dma32_compatible() {
    assert!(is_range_dma32_compatible(0, 4096));
    assert!(is_range_dma32_compatible(0xFFFF_F000, 4096));
    assert!(!is_range_dma32_compatible(0xFFFF_F000, 8192));
    assert!(!is_range_dma32_compatible(0x1_0000_0000, 1));
}

// ============================================================================
// DMA DIRECTION TESTS
// ============================================================================

#[test]
fn test_dma_direction() {
    assert!(DmaDirection::ToDevice.writes_to_device());
    assert!(!DmaDirection::ToDevice.reads_from_device());

    assert!(!DmaDirection::FromDevice.writes_to_device());
    assert!(DmaDirection::FromDevice.reads_from_device());

    assert!(DmaDirection::Bidirectional.writes_to_device());
    assert!(DmaDirection::Bidirectional.reads_from_device());
}

#[test]
fn test_dma_direction_default() {
    let dir = DmaDirection::default();
    assert_eq!(dir, DmaDirection::Bidirectional);
}

// ============================================================================
// DMA CONSTRAINTS TESTS
// ============================================================================

#[test]
fn test_dma_constraints_default() {
    let constraints = DmaConstraints::default();
    assert_eq!(constraints.alignment, 4096);
    assert_eq!(constraints.max_segment_size, 1024 * 1024);
    assert!(!constraints.dma32_only);
    assert!(constraints.coherent);
}

#[test]
fn test_dma_constraints_new() {
    let constraints = DmaConstraints::new();
    assert_eq!(constraints.alignment, DEFAULT_ALIGNMENT);
    assert!(constraints.coherent);
}

#[test]
fn test_dma_constraints_dma32() {
    let constraints = DmaConstraints::dma32();
    assert!(constraints.dma32_only);
    assert!(constraints.coherent);
}

#[test]
fn test_dma_constraints_non_coherent() {
    let constraints = DmaConstraints::non_coherent();
    assert!(!constraints.dma32_only);
    assert!(!constraints.coherent);
}

#[test]
fn test_dma_constraints_is_satisfied() {
    let constraints = DmaConstraints::default();

    // Aligned, within limits
    assert!(constraints.is_satisfied(0x1000, 4096));

    // Not aligned
    assert!(!constraints.is_satisfied(0x1001, 4096));

    // DMA32 constraints
    let dma32 = DmaConstraints::dma32();
    assert!(dma32.is_satisfied(0x1000, 4096));
    assert!(!dma32.is_satisfied(0x1_0000_0000, 4096));
}

// ============================================================================
// DMA REGION TESTS
// ============================================================================

#[test]
fn test_dma_region_creation() {
    use x86_64::{PhysAddr, VirtAddr};

    let region = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        true,
        false,
    );

    assert_eq!(region.virt_addr.as_u64(), 0x1000);
    assert_eq!(region.phys_addr.as_u64(), 0x2000);
    assert_eq!(region.size, 4096);
    assert!(region.coherent);
    assert!(!region.dma32_compatible);
}

#[test]
fn test_dma_region_dma_addr() {
    use x86_64::{PhysAddr, VirtAddr};

    let region = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        true,
        false,
    );

    assert_eq!(region.dma_addr(), 0x2000);
}

#[test]
fn test_dma_region_page_count() {
    use x86_64::{PhysAddr, VirtAddr};

    let region1 = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        true,
        false,
    );
    assert_eq!(region1.page_count(), 1);

    let region2 = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        8192,
        true,
        false,
    );
    assert_eq!(region2.page_count(), 2);

    let region3 = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4097,
        true,
        false,
    );
    assert_eq!(region3.page_count(), 2);
}

// ============================================================================
// STREAMING MAPPING TESTS
// ============================================================================

#[test]
fn test_streaming_mapping_creation() {
    use x86_64::{PhysAddr, VirtAddr};

    let mapping = StreamingMapping::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        DmaDirection::ToDevice,
        None,
    );

    assert_eq!(mapping.mapping_id, 1);
    assert_eq!(mapping.buffer_va.as_u64(), 0x1000);
    assert_eq!(mapping.dma_addr.as_u64(), 0x2000);
    assert_eq!(mapping.size, 4096);
    assert_eq!(mapping.direction, DmaDirection::ToDevice);
    assert!(!mapping.uses_bounce_buffer());
}

#[test]
fn test_streaming_mapping_with_bounce() {
    use x86_64::{PhysAddr, VirtAddr};

    let bounce = DmaRegion::new(
        VirtAddr::new(0x5000),
        PhysAddr::new(0x6000),
        4096,
        true,
        true,
    );

    let mapping = StreamingMapping::new(
        2,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x6000),
        4096,
        DmaDirection::FromDevice,
        Some(bounce),
    );

    assert!(mapping.uses_bounce_buffer());
    assert_eq!(mapping.dma_address(), 0x6000);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_dma_error_as_str() {
    assert_eq!(
        DmaError::NotInitialized.as_str(),
        "DMA allocator not initialized"
    );
    assert_eq!(
        DmaError::Dma32ConstraintFailed.as_str(),
        "DMA32 constraint not satisfied"
    );
    assert_eq!(DmaError::DoubleFree.as_str(), "Double free detected");
}

#[test]
fn test_dma_error_is_fatal() {
    assert!(DmaError::AddressSpaceExhausted.is_fatal());
    assert!(DmaError::FrameAllocationFailed.is_fatal());
    assert!(!DmaError::NotInitialized.is_fatal());
}

#[test]
fn test_dma_error_is_bug() {
    assert!(DmaError::DoubleFree.is_bug());
    assert!(DmaError::NotInPool.is_bug());
    assert!(DmaError::RegionNotFound.is_bug());
    assert!(!DmaError::NotInitialized.is_bug());
}

#[test]
fn test_dma_error_is_recoverable() {
    assert!(DmaError::NotInitialized.is_recoverable());
    assert!(DmaError::InvalidSize.is_recoverable());
    assert!(DmaError::Dma32ConstraintFailed.is_recoverable());
    assert!(!DmaError::DoubleFree.is_recoverable());
}

#[test]
fn test_dma_error_display() {
    let error = DmaError::RegionNotFound;
    let msg = format!("{}", error);
    assert_eq!(msg, "DMA region not found");
}

#[test]
fn test_dma_error_from_str() {
    assert_eq!(
        DmaError::from("DMA allocator not initialized"),
        DmaError::NotInitialized
    );
    assert_eq!(
        DmaError::from("DMA32 constraint not satisfied"),
        DmaError::Dma32ConstraintFailed
    );
    assert_eq!(
        DmaError::from("Double free detected"),
        DmaError::DoubleFree
    );
}

// ============================================================================
// STATS TESTS
// ============================================================================

#[test]
fn test_dma_stats_snapshot_default() {
    let stats = DmaStatsSnapshot::default();
    assert_eq!(stats.coherent_allocations, 0);
    assert_eq!(stats.streaming_mappings, 0);
    assert_eq!(stats.bounce_buffer_usage, 0);
    assert_eq!(stats.total_dma_memory, 0);
    assert_eq!(stats.dma_operations, 0);
}

#[test]
fn test_dma_stats_snapshot_new() {
    let stats = DmaStatsSnapshot::new();
    assert_eq!(stats.coherent_allocations, 0);
    assert_eq!(stats.total_dma_memory, 0);
}
