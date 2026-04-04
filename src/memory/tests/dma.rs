// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::memory::dma::{
    DmaDirection, DmaConstraints, DmaRegion, DmaStatsSnapshot, StreamingMapping,
    DmaError,
    DEFAULT_ALIGNMENT, DEFAULT_MAX_SEGMENT_SIZE, DMA32_LIMIT, MIN_DMA_SIZE, MAX_DMA_SIZE,
    PTE_DMA_COHERENT, PTE_CACHE_DISABLE, PTE_DMA_NON_COHERENT,
    DEFAULT_POOL_REGION_SIZE, MAX_POOL_CAPACITY,
    align_up, align_down, is_aligned, pages_needed, is_dma32_compatible, is_range_dma32_compatible,
};
use x86_64::{PhysAddr, VirtAddr};

#[test]
fn test_dma_direction_to_device() {
    let dir = DmaDirection::ToDevice;
    assert!(dir.writes_to_device());
    assert!(!dir.reads_from_device());
}

#[test]
fn test_dma_direction_from_device() {
    let dir = DmaDirection::FromDevice;
    assert!(!dir.writes_to_device());
    assert!(dir.reads_from_device());
}

#[test]
fn test_dma_direction_bidirectional() {
    let dir = DmaDirection::Bidirectional;
    assert!(dir.writes_to_device());
    assert!(dir.reads_from_device());
}

#[test]
fn test_dma_direction_default() {
    let dir = DmaDirection::default();
    assert_eq!(dir, DmaDirection::Bidirectional);
}

#[test]
fn test_dma_direction_equality() {
    assert_eq!(DmaDirection::ToDevice, DmaDirection::ToDevice);
    assert_ne!(DmaDirection::ToDevice, DmaDirection::FromDevice);
}

#[test]
fn test_dma_direction_clone() {
    let dir = DmaDirection::ToDevice;
    let cloned = dir.clone();
    assert_eq!(dir, cloned);
}

#[test]
fn test_dma_direction_copy() {
    let dir1 = DmaDirection::Bidirectional;
    let dir2 = dir1;
    assert_eq!(dir1, dir2);
}

#[test]
fn test_dma_constraints_new() {
    let c = DmaConstraints::new();
    assert_eq!(c.alignment, DEFAULT_ALIGNMENT);
    assert_eq!(c.max_segment_size, DEFAULT_MAX_SEGMENT_SIZE);
    assert!(!c.dma32_only);
    assert!(c.coherent);
}

#[test]
fn test_dma_constraints_dma32() {
    let c = DmaConstraints::dma32();
    assert!(c.dma32_only);
    assert!(c.coherent);
}

#[test]
fn test_dma_constraints_non_coherent() {
    let c = DmaConstraints::non_coherent();
    assert!(!c.dma32_only);
    assert!(!c.coherent);
}

#[test]
fn test_dma_constraints_default() {
    let c = DmaConstraints::default();
    assert_eq!(c.alignment, 4096);
}

#[test]
fn test_dma_constraints_clone() {
    let c = DmaConstraints::dma32();
    let cloned = c.clone();
    assert_eq!(c.dma32_only, cloned.dma32_only);
}

#[test]
fn test_dma_constraints_copy() {
    let c1 = DmaConstraints::new();
    let c2 = c1;
    assert_eq!(c1.alignment, c2.alignment);
}

#[test]
fn test_dma_region_new() {
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
    let region = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x5000),
        4096,
        true,
        true,
    );
    assert_eq!(region.dma_addr(), 0x5000);
}

#[test]
fn test_dma_region_as_ptr() {
    let region = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        true,
        false,
    );
    assert_eq!(region.as_ptr() as u64, 0x1000);
}

#[test]
fn test_dma_region_as_mut_ptr() {
    let region = DmaRegion::new(
        VirtAddr::new(0x3000),
        PhysAddr::new(0x4000),
        4096,
        true,
        false,
    );
    assert_eq!(region.as_mut_ptr() as u64, 0x3000);
}

#[test]
fn test_dma_region_clone() {
    let region = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        true,
        true,
    );
    let cloned = region.clone();
    assert_eq!(region.virt_addr, cloned.virt_addr);
    assert_eq!(region.size, cloned.size);
}

#[test]
fn test_dma_region_copy() {
    let r1 = DmaRegion::new(
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        true,
        false,
    );
    let r2 = r1;
    assert_eq!(r1.phys_addr, r2.phys_addr);
}

#[test]
fn test_streaming_mapping_new() {
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
}

#[test]
fn test_streaming_mapping_dma_address() {
    let mapping = StreamingMapping::new(
        3,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x8000),
        8192,
        DmaDirection::Bidirectional,
        None,
    );
    assert_eq!(mapping.dma_address(), 0x8000);
}

#[test]
fn test_streaming_mapping_clone() {
    let mapping = StreamingMapping::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        DmaDirection::ToDevice,
        None,
    );
    let cloned = mapping.clone();
    assert_eq!(mapping.mapping_id, cloned.mapping_id);
}

#[test]
fn test_streaming_mapping_copy() {
    let m1 = StreamingMapping::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        DmaDirection::FromDevice,
        None,
    );
    let m2 = m1;
    assert_eq!(m1.size, m2.size);
}

#[test]
fn test_dma_stats_snapshot_new() {
    let stats = DmaStatsSnapshot::new();
    assert_eq!(stats.coherent_allocations, 0);
    assert_eq!(stats.streaming_mappings, 0);
    assert_eq!(stats.bounce_buffer_usage, 0);
    assert_eq!(stats.total_dma_memory, 0);
    assert_eq!(stats.dma_operations, 0);
}

#[test]
fn test_dma_stats_snapshot_default() {
    let stats = DmaStatsSnapshot::default();
    assert_eq!(stats.coherent_allocations, 0);
}

#[test]
fn test_dma_stats_snapshot_clone() {
    let stats = DmaStatsSnapshot {
        coherent_allocations: 10,
        streaming_mappings: 5,
        bounce_buffer_usage: 3,
        total_dma_memory: 100000,
        dma_operations: 50,
    };
    let cloned = stats.clone();
    assert_eq!(stats.coherent_allocations, cloned.coherent_allocations);
}

#[test]
fn test_dma_error_as_str() {
    assert_eq!(DmaError::NotInitialized.as_str(), "DMA allocator not initialized");
    assert_eq!(DmaError::InvalidSize.as_str(), "Invalid allocation size");
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
    assert!(!DmaError::InvalidSize.is_bug());
}

#[test]
fn test_dma_error_is_recoverable() {
    assert!(DmaError::NotInitialized.is_recoverable());
    assert!(DmaError::InvalidSize.is_recoverable());
    assert!(!DmaError::DoubleFree.is_recoverable());
}

#[test]
fn test_dma_error_equality() {
    assert_eq!(DmaError::NotInitialized, DmaError::NotInitialized);
    assert_ne!(DmaError::NotInitialized, DmaError::InvalidSize);
}

#[test]
fn test_dma_error_clone() {
    let err = DmaError::MappingFailed;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_dma_error_copy() {
    let err1 = DmaError::PoolFull;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_default_alignment_constant() {
    assert_eq!(DEFAULT_ALIGNMENT, 4096);
}

#[test]
fn test_default_max_segment_size_constant() {
    assert_eq!(DEFAULT_MAX_SEGMENT_SIZE, 1024 * 1024);
}

#[test]
fn test_dma32_limit_constant() {
    assert_eq!(DMA32_LIMIT, 0x1_0000_0000);
}

#[test]
fn test_min_dma_size_constant() {
    assert_eq!(MIN_DMA_SIZE, 1);
}

#[test]
fn test_max_dma_size_constant() {
    assert_eq!(MAX_DMA_SIZE, 256 * 1024 * 1024);
}

#[test]
fn test_pte_dma_coherent_constant() {
    assert_eq!(PTE_DMA_COHERENT, 0x03);
}

#[test]
fn test_pte_cache_disable_constant() {
    assert_eq!(PTE_CACHE_DISABLE, 0x10);
}

#[test]
fn test_pte_dma_non_coherent_constant() {
    assert_eq!(PTE_DMA_NON_COHERENT, PTE_DMA_COHERENT | PTE_CACHE_DISABLE);
}

#[test]
fn test_default_pool_region_size_constant() {
    assert_eq!(DEFAULT_POOL_REGION_SIZE, 4096);
}

#[test]
fn test_max_pool_capacity_constant() {
    assert_eq!(MAX_POOL_CAPACITY, 1024);
}

#[test]
fn test_align_up_zero() {
    assert_eq!(align_up(0, 4096), 0);
}

#[test]
fn test_align_up_aligned() {
    assert_eq!(align_up(4096, 4096), 4096);
}

#[test]
fn test_align_up_unaligned() {
    assert_eq!(align_up(1, 4096), 4096);
    assert_eq!(align_up(4097, 4096), 8192);
}

#[test]
fn test_align_down_zero() {
    assert_eq!(align_down(0, 4096), 0);
}

#[test]
fn test_align_down_aligned() {
    assert_eq!(align_down(4096, 4096), 4096);
}

#[test]
fn test_align_down_unaligned() {
    assert_eq!(align_down(1, 4096), 0);
    assert_eq!(align_down(8000, 4096), 4096);
}

#[test]
fn test_is_aligned_true() {
    assert!(is_aligned(0, 4096));
    assert!(is_aligned(4096, 4096));
    assert!(is_aligned(8192, 4096));
}

#[test]
fn test_is_aligned_false() {
    assert!(!is_aligned(1, 4096));
    assert!(!is_aligned(4097, 4096));
}

#[test]
fn test_pages_needed_zero() {
    assert_eq!(pages_needed(0), 0);
}

#[test]
fn test_pages_needed_exact() {
    assert_eq!(pages_needed(4096), 1);
    assert_eq!(pages_needed(8192), 2);
}

#[test]
fn test_pages_needed_partial() {
    assert_eq!(pages_needed(1), 1);
    assert_eq!(pages_needed(4097), 2);
}

#[test]
fn test_is_dma32_compatible_true() {
    assert!(is_dma32_compatible(0));
    assert!(is_dma32_compatible(0x1000));
    assert!(is_dma32_compatible(0xFFFF_FFFF));
}

#[test]
fn test_is_dma32_compatible_false() {
    assert!(!is_dma32_compatible(0x1_0000_0000));
    assert!(!is_dma32_compatible(0x2_0000_0000));
}

#[test]
fn test_is_range_dma32_compatible_true() {
    assert!(is_range_dma32_compatible(0, 4096));
    assert!(is_range_dma32_compatible(0xFFFF_F000, 4096));
}

#[test]
fn test_is_range_dma32_compatible_false() {
    assert!(!is_range_dma32_compatible(0xFFFF_F000, 8192));
    assert!(!is_range_dma32_compatible(0x1_0000_0000, 1));
}

#[test]
fn test_dma_error_all_variants() {
    let errors = [
        DmaError::NotInitialized,
        DmaError::InvalidSize,
        DmaError::FrameAllocationFailed,
        DmaError::Dma32ConstraintFailed,
        DmaError::AddressSpaceExhausted,
        DmaError::MappingFailed,
        DmaError::UnmappingFailed,
        DmaError::RegionNotFound,
        DmaError::MappingNotFound,
        DmaError::TranslationFailed,
        DmaError::PoolFull,
        DmaError::DoubleFree,
        DmaError::NotInPool,
        DmaError::InvalidAlignment,
        DmaError::BufferNotFound,
    ];
    for err in errors {
        assert!(!err.as_str().is_empty());
    }
}

#[test]
fn test_dma_direction_all_variants() {
    let directions = [
        DmaDirection::ToDevice,
        DmaDirection::FromDevice,
        DmaDirection::Bidirectional,
    ];
    for dir in directions {
        let cloned = dir.clone();
        assert_eq!(dir, cloned);
    }
}

