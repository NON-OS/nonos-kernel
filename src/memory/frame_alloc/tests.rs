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
use super::error::FrameAllocError;
// ============================================================================
// CONSTANTS TESTS
// ============================================================================
#[test]
fn test_frame_size_is_4k() {
    assert_eq!(FRAME_SIZE, 4096);
    assert_eq!(FRAME_SIZE_USIZE, 4096);
}

#[test]
fn test_frame_alignment_matches_size() {
    assert_eq!(FRAME_ALIGNMENT, FRAME_SIZE);
}

#[test]
fn test_default_region_bounds() {
    assert!(DEFAULT_REGION_START < DEFAULT_REGION_END);
    assert_eq!(DEFAULT_REGION_START, 16 * 1024 * 1024); // 16 MiB
    assert_eq!(DEFAULT_REGION_END, 512 * 1024 * 1024);  // 512 MiB
}

#[test]
fn test_default_region_is_aligned() {
    assert_eq!(DEFAULT_REGION_START % FRAME_SIZE, 0);
    assert_eq!(DEFAULT_REGION_END % FRAME_SIZE, 0);
}
// ============================================================================
// ERROR TESTS
// ============================================================================
#[test]
fn test_error_display() {
    let err = FrameAllocError::OutOfFrames;
    assert_eq!(err.as_str(), "No physical frames available");
}

#[test]
fn test_error_recoverable() {
    assert!(FrameAllocError::OutOfFrames.is_recoverable());
    assert!(FrameAllocError::AlreadyInitialized.is_recoverable());
    assert!(!FrameAllocError::NotInitialized.is_recoverable());
    assert!(!FrameAllocError::DoubleFree.is_recoverable());
}

#[test]
fn test_error_from_string() {
    let err: FrameAllocError = "Invalid region: start >= end".into();
    assert_eq!(err, FrameAllocError::InvalidRegion);
    let err: FrameAllocError = "Region boundaries must be page-aligned".into();
    assert_eq!(err, FrameAllocError::RegionNotAligned);
}
// ============================================================================
// FRAME RANGE TESTS
// ============================================================================
#[test]
fn test_frame_range_valid_creation() {
    let start = PhysAddr::new(0x100000);
    let end = PhysAddr::new(0x200000);
    let range = FrameRange::new(start, end);
    assert!(range.is_ok());
}

#[test]
fn test_frame_range_invalid_start_ge_end() {
    let start = PhysAddr::new(0x200000);
    let end = PhysAddr::new(0x100000);
    let range = FrameRange::new(start, end);
    assert_eq!(range, Err(FrameAllocError::InvalidRegion));
}

#[test]
fn test_frame_range_unaligned_start() {
    let start = PhysAddr::new(0x100001); // Not aligned
    let end = PhysAddr::new(0x200000);
    let range = FrameRange::new(start, end);
    assert_eq!(range, Err(FrameAllocError::RegionNotAligned));
}

#[test]
fn test_frame_range_unaligned_end() {
    let start = PhysAddr::new(0x100000);
    let end = PhysAddr::new(0x200001); // Not aligned
    let range = FrameRange::new(start, end);
    assert_eq!(range, Err(FrameAllocError::RegionNotAligned));
}

#[test]
fn test_frame_range_frames_remaining() {
    let start = PhysAddr::new(0x100000);
    let end = PhysAddr::new(0x100000 + FRAME_SIZE * 10); // 10 frames
    let range = FrameRange::new(start, end).unwrap();
    assert_eq!(range.frames_remaining(), 10);
}

#[test]
fn test_frame_range_next_frame() {
    let start = PhysAddr::new(0x100000);
    let end = PhysAddr::new(0x100000 + FRAME_SIZE * 2); // 2 frames
    let mut range = FrameRange::new(start, end).unwrap();
    let frame1 = range.next_frame();
    assert!(frame1.is_some());
    assert_eq!(frame1.unwrap().start_address().as_u64(), 0x100000);
    let frame2 = range.next_frame();
    assert!(frame2.is_some());
    assert_eq!(frame2.unwrap().start_address().as_u64(), 0x100000 + FRAME_SIZE);
    let frame3 = range.next_frame();
    assert!(frame3.is_none());
}

#[test]
fn test_frame_range_exhausted() {
    let start = PhysAddr::new(0x100000);
    let end = PhysAddr::new(0x100000 + FRAME_SIZE);
    let mut range = FrameRange::new(start, end).unwrap();
    assert!(!range.is_exhausted());
    let _ = range.next_frame();
    assert!(range.is_exhausted());
}
// ============================================================================
// FRAME ALLOCATOR TESTS
// ============================================================================
#[test]
fn test_allocator_new() {
    let allocator = FrameAllocator::new();
    assert!(!allocator.is_initialized());
    assert_eq!(allocator.total_allocated(), 0);
    assert_eq!(allocator.regions_available(), 0);
}

#[test]
fn test_allocator_add_region() {
    let mut allocator = FrameAllocator::new();
    let start = PhysAddr::new(0x100000);
    let end = PhysAddr::new(0x200000);
    let result = allocator.add_region(start, end);
    assert!(result.is_ok());
    assert_eq!(allocator.regions_available(), 1);
}

#[test]
fn test_allocator_add_invalid_region() {
    let mut allocator = FrameAllocator::new();
    let start = PhysAddr::new(0x200000);
    let end = PhysAddr::new(0x100000);
    let result = allocator.add_region(start, end);
    assert_eq!(result, Err(FrameAllocError::InvalidRegion));
}

#[test]
fn test_allocator_max_regions() {
    let mut allocator = FrameAllocator::new();
    for i in 0..MAX_MEMORY_REGIONS {
        let start = PhysAddr::new((i as u64 + 1) * 0x100000);
        let end = PhysAddr::new((i as u64 + 1) * 0x100000 + FRAME_SIZE);
        assert!(allocator.add_region(start, end).is_ok());
    }

    // Next one should fail
    let start = PhysAddr::new(0x10000000);
    let end = PhysAddr::new(0x10001000);
    assert_eq!(allocator.add_region(start, end), Err(FrameAllocError::TooManyRegions));
}

#[test]
fn test_allocator_alloc_without_init() {
    let mut allocator = FrameAllocator::new();
    let _ = allocator.add_region(PhysAddr::new(0x100000), PhysAddr::new(0x200000));
    assert!(allocator.alloc().is_none());
}

#[test]
fn test_allocator_dealloc_without_init() {
    let allocator = FrameAllocator::new();
    let frame = PhysFrame::containing_address(PhysAddr::new(0x100000));
    let result = allocator.dealloc(frame);
    assert_eq!(result, Err(FrameAllocError::NotInitialized));
}

#[test]
fn test_allocator_total_frames_remaining() {
    let mut allocator = FrameAllocator::new();
    let _ = allocator.add_region(
        PhysAddr::new(0x100000),
        PhysAddr::new(0x100000 + FRAME_SIZE * 5),
    );
    let _ = allocator.add_region(
        PhysAddr::new(0x200000),
        PhysAddr::new(0x200000 + FRAME_SIZE * 5),
    );
    assert_eq!(allocator.total_frames_remaining(), 10);
}
// ============================================================================
// STATISTICS TESTS
// ============================================================================
#[test]
fn test_stats_initial() {
    let allocator = FrameAllocator::new();
    assert_eq!(allocator.total_allocated(), 0);
    assert_eq!(allocator.regions_available(), 0);
}
