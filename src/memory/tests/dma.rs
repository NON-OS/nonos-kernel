// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// DMA memory management tests

use crate::memory::dma::{
    align_down, align_up, is_aligned, is_dma32_compatible, is_range_dma32_compatible, pages_needed,
    DmaConstraints, DmaDirection, DmaError, DmaRegion, DmaStatsSnapshot, StreamingMapping,
    DEFAULT_ALIGNMENT, DEFAULT_MAX_SEGMENT_SIZE, DEFAULT_POOL_REGION_SIZE, DMA32_LIMIT,
    MAX_DMA_SIZE, MAX_POOL_CAPACITY, MIN_DMA_SIZE, PTE_CACHE_DISABLE, PTE_DMA_COHERENT,
    PTE_DMA_NON_COHERENT,
};
use crate::test::framework::TestResult;
use crate::memory::addr::{PhysAddr, VirtAddr};

pub(crate) fn test_dma_direction_to_device() -> TestResult {
    let dir = DmaDirection::ToDevice;
    if !dir.writes_to_device() {
        return TestResult::Fail;
    }
    if dir.reads_from_device() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_direction_from_device() -> TestResult {
    let dir = DmaDirection::FromDevice;
    if dir.writes_to_device() {
        return TestResult::Fail;
    }
    if !dir.reads_from_device() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_direction_bidirectional() -> TestResult {
    let dir = DmaDirection::Bidirectional;
    if !dir.writes_to_device() {
        return TestResult::Fail;
    }
    if !dir.reads_from_device() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_direction_default() -> TestResult {
    let dir = DmaDirection::default();
    if dir != DmaDirection::Bidirectional {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_direction_equality() -> TestResult {
    if DmaDirection::ToDevice != DmaDirection::ToDevice {
        return TestResult::Fail;
    }
    if DmaDirection::ToDevice == DmaDirection::FromDevice {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_direction_clone() -> TestResult {
    let dir = DmaDirection::ToDevice;
    let cloned = dir.clone();
    if dir != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_direction_copy() -> TestResult {
    let dir1 = DmaDirection::Bidirectional;
    let dir2 = dir1;
    if dir1 != dir2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_constraints_new() -> TestResult {
    let c = DmaConstraints::new();
    if c.alignment != DEFAULT_ALIGNMENT {
        return TestResult::Fail;
    }
    if c.max_segment_size != DEFAULT_MAX_SEGMENT_SIZE {
        return TestResult::Fail;
    }
    if c.dma32_only {
        return TestResult::Fail;
    }
    if !c.coherent {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_constraints_dma32() -> TestResult {
    let c = DmaConstraints::dma32();
    if !c.dma32_only {
        return TestResult::Fail;
    }
    if !c.coherent {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_constraints_non_coherent() -> TestResult {
    let c = DmaConstraints::non_coherent();
    if c.dma32_only {
        return TestResult::Fail;
    }
    if c.coherent {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_constraints_default() -> TestResult {
    let c = DmaConstraints::default();
    if c.alignment != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_constraints_clone() -> TestResult {
    let c = DmaConstraints::dma32();
    let cloned = c.clone();
    if c.dma32_only != cloned.dma32_only {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_constraints_copy() -> TestResult {
    let c1 = DmaConstraints::new();
    let c2 = c1;
    if c1.alignment != c2.alignment {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_region_new() -> TestResult {
    let region = DmaRegion::new(VirtAddr::new(0x1000), PhysAddr::new(0x2000), 4096, true, false);
    if region.virt_addr.as_u64() != 0x1000 {
        return TestResult::Fail;
    }
    if region.phys_addr.as_u64() != 0x2000 {
        return TestResult::Fail;
    }
    if region.size != 4096 {
        return TestResult::Fail;
    }
    if !region.coherent {
        return TestResult::Fail;
    }
    if region.dma32_compatible {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_region_dma_addr() -> TestResult {
    let region = DmaRegion::new(VirtAddr::new(0x1000), PhysAddr::new(0x5000), 4096, true, true);
    if region.dma_addr() != 0x5000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_region_as_ptr() -> TestResult {
    let region = DmaRegion::new(VirtAddr::new(0x1000), PhysAddr::new(0x2000), 4096, true, false);
    if region.as_ptr() as u64 != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_region_as_mut_ptr() -> TestResult {
    let region = DmaRegion::new(VirtAddr::new(0x3000), PhysAddr::new(0x4000), 4096, true, false);
    if region.as_mut_ptr() as u64 != 0x3000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_region_clone() -> TestResult {
    let region = DmaRegion::new(VirtAddr::new(0x1000), PhysAddr::new(0x2000), 4096, true, true);
    let cloned = region.clone();
    if region.virt_addr != cloned.virt_addr {
        return TestResult::Fail;
    }
    if region.size != cloned.size {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_region_copy() -> TestResult {
    let r1 = DmaRegion::new(VirtAddr::new(0x1000), PhysAddr::new(0x2000), 4096, true, false);
    let r2 = r1;
    if r1.phys_addr != r2.phys_addr {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_streaming_mapping_new() -> TestResult {
    let mapping = StreamingMapping::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        DmaDirection::ToDevice,
        None,
    );
    if mapping.mapping_id != 1 {
        return TestResult::Fail;
    }
    if mapping.buffer_va.as_u64() != 0x1000 {
        return TestResult::Fail;
    }
    if mapping.dma_addr.as_u64() != 0x2000 {
        return TestResult::Fail;
    }
    if mapping.size != 4096 {
        return TestResult::Fail;
    }
    if mapping.direction != DmaDirection::ToDevice {
        return TestResult::Fail;
    }
    if mapping.uses_bounce_buffer() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_streaming_mapping_with_bounce() -> TestResult {
    let bounce = DmaRegion::new(VirtAddr::new(0x5000), PhysAddr::new(0x6000), 4096, true, true);
    let mapping = StreamingMapping::new(
        2,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x6000),
        4096,
        DmaDirection::FromDevice,
        Some(bounce),
    );
    if !mapping.uses_bounce_buffer() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_streaming_mapping_dma_address() -> TestResult {
    let mapping = StreamingMapping::new(
        3,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x8000),
        8192,
        DmaDirection::Bidirectional,
        None,
    );
    if mapping.dma_address() != 0x8000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_streaming_mapping_clone() -> TestResult {
    let mapping = StreamingMapping::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        DmaDirection::ToDevice,
        None,
    );
    let cloned = mapping.clone();
    if mapping.mapping_id != cloned.mapping_id {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_streaming_mapping_copy() -> TestResult {
    let m1 = StreamingMapping::new(
        1,
        VirtAddr::new(0x1000),
        PhysAddr::new(0x2000),
        4096,
        DmaDirection::FromDevice,
        None,
    );
    let m2 = m1;
    if m1.size != m2.size {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_stats_snapshot_new() -> TestResult {
    let stats = DmaStatsSnapshot::new();
    if stats.coherent_allocations != 0 {
        return TestResult::Fail;
    }
    if stats.streaming_mappings != 0 {
        return TestResult::Fail;
    }
    if stats.bounce_buffer_usage != 0 {
        return TestResult::Fail;
    }
    if stats.total_dma_memory != 0 {
        return TestResult::Fail;
    }
    if stats.dma_operations != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_stats_snapshot_default() -> TestResult {
    let stats = DmaStatsSnapshot::default();
    if stats.coherent_allocations != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_stats_snapshot_clone() -> TestResult {
    let stats = DmaStatsSnapshot {
        coherent_allocations: 10,
        streaming_mappings: 5,
        bounce_buffer_usage: 3,
        total_dma_memory: 100000,
        dma_operations: 50,
    };
    let cloned = stats.clone();
    if stats.coherent_allocations != cloned.coherent_allocations {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_error_as_str() -> TestResult {
    if DmaError::NotInitialized.as_str() != "DMA allocator not initialized" {
        return TestResult::Fail;
    }
    if DmaError::InvalidSize.as_str() != "Invalid allocation size" {
        return TestResult::Fail;
    }
    if DmaError::DoubleFree.as_str() != "Double free detected" {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_error_is_fatal() -> TestResult {
    if !DmaError::AddressSpaceExhausted.is_fatal() {
        return TestResult::Fail;
    }
    if !DmaError::FrameAllocationFailed.is_fatal() {
        return TestResult::Fail;
    }
    if DmaError::NotInitialized.is_fatal() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_error_is_bug() -> TestResult {
    if !DmaError::DoubleFree.is_bug() {
        return TestResult::Fail;
    }
    if !DmaError::NotInPool.is_bug() {
        return TestResult::Fail;
    }
    if DmaError::InvalidSize.is_bug() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_error_is_recoverable() -> TestResult {
    if !DmaError::NotInitialized.is_recoverable() {
        return TestResult::Fail;
    }
    if !DmaError::InvalidSize.is_recoverable() {
        return TestResult::Fail;
    }
    if DmaError::DoubleFree.is_recoverable() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_error_equality() -> TestResult {
    if DmaError::NotInitialized != DmaError::NotInitialized {
        return TestResult::Fail;
    }
    if DmaError::NotInitialized == DmaError::InvalidSize {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_error_clone() -> TestResult {
    let err = DmaError::MappingFailed;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_error_copy() -> TestResult {
    let err1 = DmaError::PoolFull;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_alignment_constant() -> TestResult {
    if DEFAULT_ALIGNMENT != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_max_segment_size_constant() -> TestResult {
    if DEFAULT_MAX_SEGMENT_SIZE != 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma32_limit_constant() -> TestResult {
    if DMA32_LIMIT != 0x1_0000_0000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_min_dma_size_constant() -> TestResult {
    if MIN_DMA_SIZE != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_dma_size_constant() -> TestResult {
    if MAX_DMA_SIZE != 256 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_dma_coherent_constant() -> TestResult {
    if PTE_DMA_COHERENT != 0x03 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_cache_disable_constant() -> TestResult {
    if PTE_CACHE_DISABLE != 0x10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pte_dma_non_coherent_constant() -> TestResult {
    if PTE_DMA_NON_COHERENT != PTE_DMA_COHERENT | PTE_CACHE_DISABLE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_default_pool_region_size_constant() -> TestResult {
    if DEFAULT_POOL_REGION_SIZE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_pool_capacity_constant() -> TestResult {
    if MAX_POOL_CAPACITY != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_up_zero() -> TestResult {
    if align_up(0, 4096) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_up_aligned() -> TestResult {
    if align_up(4096, 4096) != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_up_unaligned() -> TestResult {
    if align_up(1, 4096) != 4096 {
        return TestResult::Fail;
    }
    if align_up(4097, 4096) != 8192 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_down_zero() -> TestResult {
    if align_down(0, 4096) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_down_aligned() -> TestResult {
    if align_down(4096, 4096) != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_down_unaligned() -> TestResult {
    if align_down(1, 4096) != 0 {
        return TestResult::Fail;
    }
    if align_down(8000, 4096) != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_aligned_true() -> TestResult {
    if !is_aligned(0, 4096) {
        return TestResult::Fail;
    }
    if !is_aligned(4096, 4096) {
        return TestResult::Fail;
    }
    if !is_aligned(8192, 4096) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_aligned_false() -> TestResult {
    if is_aligned(1, 4096) {
        return TestResult::Fail;
    }
    if is_aligned(4097, 4096) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pages_needed_zero() -> TestResult {
    if pages_needed(0) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pages_needed_exact() -> TestResult {
    if pages_needed(4096) != 1 {
        return TestResult::Fail;
    }
    if pages_needed(8192) != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_pages_needed_partial() -> TestResult {
    if pages_needed(1) != 1 {
        return TestResult::Fail;
    }
    if pages_needed(4097) != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_dma32_compatible_true() -> TestResult {
    if !is_dma32_compatible(0) {
        return TestResult::Fail;
    }
    if !is_dma32_compatible(0x1000) {
        return TestResult::Fail;
    }
    if !is_dma32_compatible(0xFFFF_FFFF) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_dma32_compatible_false() -> TestResult {
    if is_dma32_compatible(0x1_0000_0000) {
        return TestResult::Fail;
    }
    if is_dma32_compatible(0x2_0000_0000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_range_dma32_compatible_true() -> TestResult {
    if !is_range_dma32_compatible(0, 4096) {
        return TestResult::Fail;
    }
    if !is_range_dma32_compatible(0xFFFF_F000, 4096) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_range_dma32_compatible_false() -> TestResult {
    if is_range_dma32_compatible(0xFFFF_F000, 8192) {
        return TestResult::Fail;
    }
    if is_range_dma32_compatible(0x1_0000_0000, 1) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dma_error_all_variants() -> TestResult {
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
        if err.as_str().is_empty() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_dma_direction_all_variants() -> TestResult {
    let directions =
        [DmaDirection::ToDevice, DmaDirection::FromDevice, DmaDirection::Bidirectional];
    for dir in directions {
        let cloned = dir.clone();
        if dir != cloned {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
