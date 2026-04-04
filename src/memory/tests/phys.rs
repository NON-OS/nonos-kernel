use crate::memory::phys::{
    Frame, PhysFrame, AllocFlags, ZoneStats, AllocatorState, PhysAllocError,
    PAGE_SIZE, PAGE_SIZE_U64, BITS_PER_BYTE,
    MAX_PHYSICAL_MEMORY, MAX_FRAME_COUNT, MAX_BITMAP_SIZE,
    align_up, align_down, bitmap_bytes_for_frames, frames_in_range,
};
use x86_64::PhysAddr;

#[test]
fn test_frame_new() {
    let frame = Frame::new(0x1000);
    assert_eq!(frame.addr(), 0x1000);
}

#[test]
fn test_frame_addr() {
    let frame = Frame::new(0x2000);
    assert_eq!(frame.addr(), 0x2000);
}

#[test]
fn test_frame_as_phys_addr() {
    let frame = Frame::new(0x3000);
    assert_eq!(frame.as_phys_addr(), PhysAddr::new(0x3000));
}

#[test]
fn test_frame_from_phys_addr() {
    let phys = PhysAddr::new(0x4000);
    let frame = Frame::from_phys_addr(phys);
    assert_eq!(frame.addr(), 0x4000);
}

#[test]
fn test_frame_number() {
    let frame = Frame::new(0x5000);
    assert_eq!(frame.number(0, PAGE_SIZE_U64), 5);
}

#[test]
fn test_frame_number_with_base() {
    let frame = Frame::new(0x6000);
    assert_eq!(frame.number(0x1000, PAGE_SIZE_U64), 5);
}

#[test]
fn test_frame_is_null() {
    let null_frame = Frame::new(0);
    let valid_frame = Frame::new(0x1000);
    assert!(null_frame.is_null());
    assert!(!valid_frame.is_null());
}

#[test]
fn test_frame_equality() {
    let f1 = Frame::new(0x1000);
    let f2 = Frame::new(0x1000);
    let f3 = Frame::new(0x2000);
    assert_eq!(f1, f2);
    assert_ne!(f1, f3);
}

#[test]
fn test_frame_clone() {
    let frame = Frame::new(0x7000);
    let cloned = frame.clone();
    assert_eq!(frame, cloned);
}

#[test]
fn test_phys_frame_alias() {
    let frame: PhysFrame = Frame::new(0x8000);
    assert_eq!(frame.addr(), 0x8000);
}

#[test]
fn test_alloc_flags_empty() {
    let flags = AllocFlags::EMPTY;
    assert_eq!(flags.bits(), 0);
}

#[test]
fn test_alloc_flags_zero() {
    let flags = AllocFlags::ZERO;
    assert!(flags.contains(AllocFlags::ZERO));
    assert!(!flags.contains(AllocFlags::HIGH));
}

#[test]
fn test_alloc_flags_high() {
    let flags = AllocFlags::HIGH;
    assert!(flags.contains(AllocFlags::HIGH));
}

#[test]
fn test_alloc_flags_dma() {
    let flags = AllocFlags::DMA;
    assert!(flags.contains(AllocFlags::DMA));
}

#[test]
fn test_alloc_flags_contiguous() {
    let flags = AllocFlags::CONTIGUOUS;
    assert!(flags.contains(AllocFlags::CONTIGUOUS));
}

#[test]
fn test_alloc_flags_combined() {
    let flags = AllocFlags::ZERO | AllocFlags::HIGH;
    assert!(flags.contains(AllocFlags::ZERO));
    assert!(flags.contains(AllocFlags::HIGH));
}

#[test]
fn test_alloc_flags_default() {
    let flags = AllocFlags::default();
    assert_eq!(flags, AllocFlags::EMPTY);
}

#[test]
fn test_zone_stats_new() {
    let stats = ZoneStats::new(100, 50);
    assert_eq!(stats.frames_total, 100);
    assert_eq!(stats.frames_free, 50);
}

#[test]
fn test_zone_stats_frames_allocated() {
    let stats = ZoneStats::new(100, 40);
    assert_eq!(stats.frames_allocated(), 60);
}

#[test]
fn test_zone_stats_usage_percent() {
    let stats = ZoneStats::new(100, 50);
    assert_eq!(stats.usage_percent(), 50);
}

#[test]
fn test_zone_stats_usage_percent_zero_total() {
    let stats = ZoneStats::new(0, 0);
    assert_eq!(stats.usage_percent(), 0);
}

#[test]
fn test_zone_stats_total_bytes() {
    let stats = ZoneStats::new(10, 5);
    assert_eq!(stats.total_bytes(PAGE_SIZE), 10 * PAGE_SIZE);
}

#[test]
fn test_zone_stats_free_bytes() {
    let stats = ZoneStats::new(10, 5);
    assert_eq!(stats.free_bytes(PAGE_SIZE), 5 * PAGE_SIZE);
}

#[test]
fn test_zone_stats_default() {
    let stats = ZoneStats::default();
    assert_eq!(stats.frames_total, 0);
    assert_eq!(stats.frames_free, 0);
}

#[test]
fn test_zone_stats_clone() {
    let stats = ZoneStats::new(100, 50);
    let cloned = stats.clone();
    assert_eq!(stats.frames_total, cloned.frames_total);
    assert_eq!(stats.frames_free, cloned.frames_free);
}

#[test]
fn test_allocator_state_new() {
    let state = AllocatorState::new();
    assert_eq!(state.frame_start, 0);
    assert_eq!(state.frame_count, 0);
    assert!(state.bitmap_ptr.is_null());
    assert_eq!(state.bitmap_bytes, 0);
    assert_eq!(state.next_hint, 0);
    assert_eq!(state.random_seed, 0);
}

#[test]
fn test_allocator_state_is_initialized_false() {
    let state = AllocatorState::new();
    assert!(!state.is_initialized());
}

#[test]
fn test_allocator_state_default() {
    let state = AllocatorState::default();
    assert!(!state.is_initialized());
}

#[test]
fn test_phys_alloc_error_variants() {
    assert_eq!(PhysAllocError::NotInitialized, PhysAllocError::NotInitialized);
    assert_eq!(PhysAllocError::InvalidRange, PhysAllocError::InvalidRange);
    assert_eq!(PhysAllocError::NoCompletePagesInRange, PhysAllocError::NoCompletePagesInRange);
    assert_eq!(PhysAllocError::BitmapTooSmall, PhysAllocError::BitmapTooSmall);
    assert_eq!(PhysAllocError::InvalidBitmapPointer, PhysAllocError::InvalidBitmapPointer);
    assert_eq!(PhysAllocError::AddressBelowRange, PhysAllocError::AddressBelowRange);
    assert_eq!(PhysAllocError::AddressAboveRange, PhysAllocError::AddressAboveRange);
    assert_eq!(PhysAllocError::AddressNotAligned, PhysAllocError::AddressNotAligned);
    assert_eq!(PhysAllocError::OutOfMemory, PhysAllocError::OutOfMemory);
    assert_eq!(PhysAllocError::DoubleFree, PhysAllocError::DoubleFree);
    assert_eq!(PhysAllocError::FrameNotAllocated, PhysAllocError::FrameNotAllocated);
    assert_eq!(PhysAllocError::RangeBeyondManaged, PhysAllocError::RangeBeyondManaged);
    assert_eq!(PhysAllocError::ZeroFrameCount, PhysAllocError::ZeroFrameCount);
}

#[test]
fn test_phys_alloc_error_clone() {
    let err = PhysAllocError::DoubleFree;
    let cloned = err.clone();
    assert_eq!(err, cloned);
}

#[test]
fn test_page_size_constant() {
    assert_eq!(PAGE_SIZE, 4096);
}

#[test]
fn test_page_size_u64_constant() {
    assert_eq!(PAGE_SIZE_U64, 4096);
}

#[test]
fn test_bits_per_byte_constant() {
    assert_eq!(BITS_PER_BYTE, 8);
}

#[test]
fn test_max_physical_memory_constant() {
    assert_eq!(MAX_PHYSICAL_MEMORY, 64 * 1024 * 1024 * 1024);
}

#[test]
fn test_max_frame_count_constant() {
    assert_eq!(MAX_FRAME_COUNT, (MAX_PHYSICAL_MEMORY / PAGE_SIZE_U64) as usize);
}

#[test]
fn test_max_bitmap_size_constant() {
    assert_eq!(MAX_BITMAP_SIZE, MAX_FRAME_COUNT / BITS_PER_BYTE);
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
    assert_eq!(align_up(4097, 4096), 8192);
}

#[test]
fn test_align_up_zero_alignment() {
    assert_eq!(align_up(100, 0), 100);
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
    assert_eq!(align_down(5000, 4096), 4096);
}

#[test]
fn test_align_down_zero_alignment() {
    assert_eq!(align_down(100, 0), 100);
}

#[test]
fn test_bitmap_bytes_for_frames_exact() {
    assert_eq!(bitmap_bytes_for_frames(8), 1);
}

#[test]
fn test_bitmap_bytes_for_frames_partial() {
    assert_eq!(bitmap_bytes_for_frames(9), 2);
}

#[test]
fn test_bitmap_bytes_for_frames_zero() {
    assert_eq!(bitmap_bytes_for_frames(0), 0);
}

#[test]
fn test_bitmap_bytes_for_frames_large() {
    assert_eq!(bitmap_bytes_for_frames(1000), 125);
}

#[test]
fn test_frames_in_range_normal() {
    assert_eq!(frames_in_range(0, 4096), 1);
}

#[test]
fn test_frames_in_range_multiple() {
    assert_eq!(frames_in_range(0, 8192), 2);
}

#[test]
fn test_frames_in_range_zero() {
    assert_eq!(frames_in_range(0, 0), 0);
}

#[test]
fn test_frames_in_range_invalid() {
    assert_eq!(frames_in_range(8192, 4096), 0);
}

#[test]
fn test_frames_in_range_equal() {
    assert_eq!(frames_in_range(4096, 4096), 0);
}

#[test]
fn test_frame_copy() {
    let f1 = Frame::new(0x1000);
    let f2 = f1;
    assert_eq!(f1.addr(), f2.addr());
}

#[test]
fn test_alloc_flags_equality() {
    assert_eq!(AllocFlags::ZERO, AllocFlags::ZERO);
    assert_ne!(AllocFlags::ZERO, AllocFlags::HIGH);
}

#[test]
fn test_zone_stats_full_allocation() {
    let stats = ZoneStats::new(100, 0);
    assert_eq!(stats.frames_allocated(), 100);
    assert_eq!(stats.usage_percent(), 100);
}

#[test]
fn test_zone_stats_no_allocation() {
    let stats = ZoneStats::new(100, 100);
    assert_eq!(stats.frames_allocated(), 0);
    assert_eq!(stats.usage_percent(), 0);
}

#[test]
fn test_frame_number_below_base() {
    let frame = Frame::new(0x1000);
    assert_eq!(frame.number(0x2000, PAGE_SIZE_U64), 0);
}

#[test]
fn test_align_up_various_alignments() {
    assert_eq!(align_up(1, 16), 16);
    assert_eq!(align_up(17, 16), 32);
    assert_eq!(align_up(32, 16), 32);
}

#[test]
fn test_align_down_various_alignments() {
    assert_eq!(align_down(1, 16), 0);
    assert_eq!(align_down(17, 16), 16);
    assert_eq!(align_down(32, 16), 32);
}

#[test]
fn test_bitmap_bytes_for_frames_boundary() {
    assert_eq!(bitmap_bytes_for_frames(7), 1);
    assert_eq!(bitmap_bytes_for_frames(8), 1);
    assert_eq!(bitmap_bytes_for_frames(16), 2);
}

#[test]
fn test_alloc_flags_all_combined() {
    let flags = AllocFlags::ZERO | AllocFlags::HIGH | AllocFlags::DMA | AllocFlags::CONTIGUOUS;
    assert!(flags.contains(AllocFlags::ZERO));
    assert!(flags.contains(AllocFlags::HIGH));
    assert!(flags.contains(AllocFlags::DMA));
    assert!(flags.contains(AllocFlags::CONTIGUOUS));
}

#[test]
fn test_zone_stats_bytes_calculation() {
    let stats = ZoneStats::new(256, 128);
    assert_eq!(stats.total_bytes(4096), 256 * 4096);
    assert_eq!(stats.free_bytes(4096), 128 * 4096);
}

#[test]
fn test_frame_transparent_representation() {
    let frame = Frame::new(0xDEAD_BEEF);
    assert_eq!(frame.0, 0xDEAD_BEEF);
}

#[test]
fn test_allocator_state_fields() {
    let mut state = AllocatorState::new();
    state.frame_start = 0x1000;
    state.frame_count = 100;
    state.next_hint = 50;
    state.random_seed = 12345;
    assert_eq!(state.frame_start, 0x1000);
    assert_eq!(state.frame_count, 100);
    assert_eq!(state.next_hint, 50);
    assert_eq!(state.random_seed, 12345);
}

#[test]
fn test_phys_alloc_error_copy() {
    let err1 = PhysAllocError::OutOfMemory;
    let err2 = err1;
    assert_eq!(err1, err2);
}

#[test]
fn test_frames_in_range_large_range() {
    let start = 0u64;
    let end = 1024 * 1024 * 1024u64;
    let expected = ((end - start) / PAGE_SIZE_U64) as usize;
    assert_eq!(frames_in_range(start, end), expected);
}

#[test]
fn test_alloc_flags_bits() {
    assert_eq!(AllocFlags::EMPTY.bits(), 0);
    assert_eq!(AllocFlags::ZERO.bits(), 1 << 0);
    assert_eq!(AllocFlags::HIGH.bits(), 1 << 1);
    assert_eq!(AllocFlags::DMA.bits(), 1 << 2);
    assert_eq!(AllocFlags::CONTIGUOUS.bits(), 1 << 3);
}
