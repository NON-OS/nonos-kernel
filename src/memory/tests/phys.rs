// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Physical memory allocator tests

use crate::memory::phys::{
    align_down, align_up, bitmap_bytes_for_frames, frames_in_range, AllocFlags, AllocatorState,
    Frame, PhysAllocError, PhysFrame, ZoneStats, BITS_PER_BYTE, MAX_BITMAP_SIZE, MAX_FRAME_COUNT,
    MAX_PHYSICAL_MEMORY, PAGE_SIZE, PAGE_SIZE_U64,
};
use crate::test::framework::TestResult;
use x86_64::PhysAddr;

pub(crate) fn test_frame_new() -> TestResult {
    let frame = Frame::new(0x1000);
    if frame.addr() != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_addr() -> TestResult {
    let frame = Frame::new(0x2000);
    if frame.addr() != 0x2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_as_phys_addr() -> TestResult {
    let frame = Frame::new(0x3000);
    if frame.as_phys_addr() != PhysAddr::new(0x3000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_from_phys_addr() -> TestResult {
    let phys = PhysAddr::new(0x4000);
    let frame = Frame::from_phys_addr(phys);
    if frame.addr() != 0x4000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_number() -> TestResult {
    let frame = Frame::new(0x5000);
    if frame.number(0, PAGE_SIZE_U64) != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_number_with_base() -> TestResult {
    let frame = Frame::new(0x6000);
    if frame.number(0x1000, PAGE_SIZE_U64) != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_is_null() -> TestResult {
    let null_frame = Frame::new(0);
    let valid_frame = Frame::new(0x1000);
    if !null_frame.is_null() {
        return TestResult::Fail;
    }
    if valid_frame.is_null() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_equality() -> TestResult {
    let f1 = Frame::new(0x1000);
    let f2 = Frame::new(0x1000);
    let f3 = Frame::new(0x2000);
    if f1 != f2 {
        return TestResult::Fail;
    }
    if f1 == f3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_clone() -> TestResult {
    let frame = Frame::new(0x7000);
    let cloned = frame.clone();
    if frame != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_phys_frame_alias() -> TestResult {
    let frame: PhysFrame = Frame::new(0x8000);
    if frame.addr() != 0x8000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_empty() -> TestResult {
    let flags = AllocFlags::EMPTY;
    if flags.bits() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_zero() -> TestResult {
    let flags = AllocFlags::ZERO;
    if !flags.contains(AllocFlags::ZERO) {
        return TestResult::Fail;
    }
    if flags.contains(AllocFlags::HIGH) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_high() -> TestResult {
    let flags = AllocFlags::HIGH;
    if !flags.contains(AllocFlags::HIGH) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_dma() -> TestResult {
    let flags = AllocFlags::DMA;
    if !flags.contains(AllocFlags::DMA) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_contiguous() -> TestResult {
    let flags = AllocFlags::CONTIGUOUS;
    if !flags.contains(AllocFlags::CONTIGUOUS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_combined() -> TestResult {
    let flags = AllocFlags::ZERO | AllocFlags::HIGH;
    if !flags.contains(AllocFlags::ZERO) {
        return TestResult::Fail;
    }
    if !flags.contains(AllocFlags::HIGH) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_default() -> TestResult {
    let flags = AllocFlags::default();
    if flags != AllocFlags::EMPTY {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_new() -> TestResult {
    let stats = ZoneStats::new(100, 50);
    if stats.frames_total != 100 {
        return TestResult::Fail;
    }
    if stats.frames_free != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_frames_allocated() -> TestResult {
    let stats = ZoneStats::new(100, 40);
    if stats.frames_allocated() != 60 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_usage_percent() -> TestResult {
    let stats = ZoneStats::new(100, 50);
    if stats.usage_percent() != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_usage_percent_zero_total() -> TestResult {
    let stats = ZoneStats::new(0, 0);
    if stats.usage_percent() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_total_bytes() -> TestResult {
    let stats = ZoneStats::new(10, 5);
    if stats.total_bytes(PAGE_SIZE) != 10 * PAGE_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_free_bytes() -> TestResult {
    let stats = ZoneStats::new(10, 5);
    if stats.free_bytes(PAGE_SIZE) != 5 * PAGE_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_default() -> TestResult {
    let stats = ZoneStats::default();
    if stats.frames_total != 0 {
        return TestResult::Fail;
    }
    if stats.frames_free != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_clone() -> TestResult {
    let stats = ZoneStats::new(100, 50);
    let cloned = stats.clone();
    if stats.frames_total != cloned.frames_total {
        return TestResult::Fail;
    }
    if stats.frames_free != cloned.frames_free {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_allocator_state_new() -> TestResult {
    let state = AllocatorState::new();
    if state.frame_start != 0 {
        return TestResult::Fail;
    }
    if state.frame_count != 0 {
        return TestResult::Fail;
    }
    if !state.bitmap_ptr.is_null() {
        return TestResult::Fail;
    }
    if state.bitmap_bytes != 0 {
        return TestResult::Fail;
    }
    if state.next_hint != 0 {
        return TestResult::Fail;
    }
    if state.random_seed != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_allocator_state_is_initialized_false() -> TestResult {
    let state = AllocatorState::new();
    if state.is_initialized() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_allocator_state_default() -> TestResult {
    let state = AllocatorState::default();
    if state.is_initialized() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_phys_alloc_error_variants() -> TestResult {
    if PhysAllocError::NotInitialized != PhysAllocError::NotInitialized {
        return TestResult::Fail;
    }
    if PhysAllocError::InvalidRange != PhysAllocError::InvalidRange {
        return TestResult::Fail;
    }
    if PhysAllocError::NoCompletePagesInRange != PhysAllocError::NoCompletePagesInRange {
        return TestResult::Fail;
    }
    if PhysAllocError::BitmapTooSmall != PhysAllocError::BitmapTooSmall {
        return TestResult::Fail;
    }
    if PhysAllocError::InvalidBitmapPointer != PhysAllocError::InvalidBitmapPointer {
        return TestResult::Fail;
    }
    if PhysAllocError::AddressBelowRange != PhysAllocError::AddressBelowRange {
        return TestResult::Fail;
    }
    if PhysAllocError::AddressAboveRange != PhysAllocError::AddressAboveRange {
        return TestResult::Fail;
    }
    if PhysAllocError::AddressNotAligned != PhysAllocError::AddressNotAligned {
        return TestResult::Fail;
    }
    if PhysAllocError::OutOfMemory != PhysAllocError::OutOfMemory {
        return TestResult::Fail;
    }
    if PhysAllocError::DoubleFree != PhysAllocError::DoubleFree {
        return TestResult::Fail;
    }
    if PhysAllocError::FrameNotAllocated != PhysAllocError::FrameNotAllocated {
        return TestResult::Fail;
    }
    if PhysAllocError::RangeBeyondManaged != PhysAllocError::RangeBeyondManaged {
        return TestResult::Fail;
    }
    if PhysAllocError::ZeroFrameCount != PhysAllocError::ZeroFrameCount {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_phys_alloc_error_clone() -> TestResult {
    let err = PhysAllocError::DoubleFree;
    let cloned = err.clone();
    if err != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_constant() -> TestResult {
    if PAGE_SIZE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_page_size_u64_constant() -> TestResult {
    if PAGE_SIZE_U64 != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bits_per_byte_constant() -> TestResult {
    if BITS_PER_BYTE != 8 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_physical_memory_constant() -> TestResult {
    if MAX_PHYSICAL_MEMORY != 64 * 1024 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_frame_count_constant() -> TestResult {
    if MAX_FRAME_COUNT != (MAX_PHYSICAL_MEMORY / PAGE_SIZE_U64) as usize {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_max_bitmap_size_constant() -> TestResult {
    if MAX_BITMAP_SIZE != MAX_FRAME_COUNT / BITS_PER_BYTE {
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
    if align_up(4097, 4096) != 8192 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_up_zero_alignment() -> TestResult {
    if align_up(100, 0) != 100 {
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
    if align_down(5000, 4096) != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_down_zero_alignment() -> TestResult {
    if align_down(100, 0) != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bitmap_bytes_for_frames_exact() -> TestResult {
    if bitmap_bytes_for_frames(8) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bitmap_bytes_for_frames_partial() -> TestResult {
    if bitmap_bytes_for_frames(9) != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bitmap_bytes_for_frames_zero() -> TestResult {
    if bitmap_bytes_for_frames(0) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bitmap_bytes_for_frames_large() -> TestResult {
    if bitmap_bytes_for_frames(1000) != 125 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frames_in_range_normal() -> TestResult {
    if frames_in_range(0, 4096) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frames_in_range_multiple() -> TestResult {
    if frames_in_range(0, 8192) != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frames_in_range_zero() -> TestResult {
    if frames_in_range(0, 0) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frames_in_range_invalid() -> TestResult {
    if frames_in_range(8192, 4096) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frames_in_range_equal() -> TestResult {
    if frames_in_range(4096, 4096) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_copy() -> TestResult {
    let f1 = Frame::new(0x1000);
    let f2 = f1;
    if f1.addr() != f2.addr() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_equality() -> TestResult {
    if AllocFlags::ZERO != AllocFlags::ZERO {
        return TestResult::Fail;
    }
    if AllocFlags::ZERO == AllocFlags::HIGH {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_full_allocation() -> TestResult {
    let stats = ZoneStats::new(100, 0);
    if stats.frames_allocated() != 100 {
        return TestResult::Fail;
    }
    if stats.usage_percent() != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_no_allocation() -> TestResult {
    let stats = ZoneStats::new(100, 100);
    if stats.frames_allocated() != 0 {
        return TestResult::Fail;
    }
    if stats.usage_percent() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_number_below_base() -> TestResult {
    let frame = Frame::new(0x1000);
    if frame.number(0x2000, PAGE_SIZE_U64) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_up_various_alignments() -> TestResult {
    if align_up(1, 16) != 16 {
        return TestResult::Fail;
    }
    if align_up(17, 16) != 32 {
        return TestResult::Fail;
    }
    if align_up(32, 16) != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_align_down_various_alignments() -> TestResult {
    if align_down(1, 16) != 0 {
        return TestResult::Fail;
    }
    if align_down(17, 16) != 16 {
        return TestResult::Fail;
    }
    if align_down(32, 16) != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_bitmap_bytes_for_frames_boundary() -> TestResult {
    if bitmap_bytes_for_frames(7) != 1 {
        return TestResult::Fail;
    }
    if bitmap_bytes_for_frames(8) != 1 {
        return TestResult::Fail;
    }
    if bitmap_bytes_for_frames(16) != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_all_combined() -> TestResult {
    let flags = AllocFlags::ZERO | AllocFlags::HIGH | AllocFlags::DMA | AllocFlags::CONTIGUOUS;
    if !flags.contains(AllocFlags::ZERO) {
        return TestResult::Fail;
    }
    if !flags.contains(AllocFlags::HIGH) {
        return TestResult::Fail;
    }
    if !flags.contains(AllocFlags::DMA) {
        return TestResult::Fail;
    }
    if !flags.contains(AllocFlags::CONTIGUOUS) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_zone_stats_bytes_calculation() -> TestResult {
    let stats = ZoneStats::new(256, 128);
    if stats.total_bytes(4096) != 256 * 4096 {
        return TestResult::Fail;
    }
    if stats.free_bytes(4096) != 128 * 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frame_transparent_representation() -> TestResult {
    let frame = Frame::new(0xDEAD_BEEF);
    if frame.0 != 0xDEAD_BEEF {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_allocator_state_fields() -> TestResult {
    let mut state = AllocatorState::new();
    state.frame_start = 0x1000;
    state.frame_count = 100;
    state.next_hint = 50;
    state.random_seed = 12345;
    if state.frame_start != 0x1000 {
        return TestResult::Fail;
    }
    if state.frame_count != 100 {
        return TestResult::Fail;
    }
    if state.next_hint != 50 {
        return TestResult::Fail;
    }
    if state.random_seed != 12345 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_phys_alloc_error_copy() -> TestResult {
    let err1 = PhysAllocError::OutOfMemory;
    let err2 = err1;
    if err1 != err2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_frames_in_range_large_range() -> TestResult {
    let start = 0u64;
    let end = 1024 * 1024 * 1024u64;
    let expected = ((end - start) / PAGE_SIZE_U64) as usize;
    if frames_in_range(start, end) != expected {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_bits() -> TestResult {
    if AllocFlags::EMPTY.bits() != 0 {
        return TestResult::Fail;
    }
    if AllocFlags::ZERO.bits() != 1 << 0 {
        return TestResult::Fail;
    }
    if AllocFlags::HIGH.bits() != 1 << 1 {
        return TestResult::Fail;
    }
    if AllocFlags::DMA.bits() != 1 << 2 {
        return TestResult::Fail;
    }
    if AllocFlags::CONTIGUOUS.bits() != 1 << 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}
