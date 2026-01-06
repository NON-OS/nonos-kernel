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
use super::error::PageAllocError;

// ============================================================================
// CONSTANTS TESTS
// ============================================================================

#[test]
fn test_initial_page_id() {
    assert_eq!(INITIAL_PAGE_ID, 1);
}

#[test]
fn test_max_tracked_pages() {
    assert!(MAX_TRACKED_PAGES > 0);
    assert!(MAX_TRACKED_PAGES <= 1_000_000);
}

#[test]
fn test_zero_pattern() {
    assert_eq!(ZERO_PATTERN, 0);
}

#[test]
fn test_max_allocation_size() {
    // Should be 1 GiB
    assert_eq!(MAX_ALLOCATION_SIZE, 1024 * 1024 * 1024);
}

#[test]
fn test_min_allocation_size() {
    // Should be one page
    assert_eq!(MIN_ALLOCATION_SIZE, 4096);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_error_display() {
    let err = PageAllocError::NotInitialized;
    assert_eq!(err.as_str(), "Page allocator not initialized");
}

#[test]
fn test_error_recoverable() {
    assert!(PageAllocError::FrameAllocationFailed.is_recoverable());
    assert!(PageAllocError::OutOfVirtualSpace.is_recoverable());
    assert!(PageAllocError::AlreadyInitialized.is_recoverable());
    assert!(!PageAllocError::NotInitialized.is_recoverable());
    assert!(!PageAllocError::PageNotFound.is_recoverable());
}

#[test]
fn test_error_from_string() {
    let err: PageAllocError = "Page allocator not initialized".into();
    assert_eq!(err, PageAllocError::NotInitialized);

    let err: PageAllocError = "Invalid allocation size".into();
    assert_eq!(err, PageAllocError::InvalidSize);

    let err: PageAllocError = "Page not found".into();
    assert_eq!(err, PageAllocError::PageNotFound);
}

// ============================================================================
// PAGE ALLOCATOR STATS TESTS
// ============================================================================

#[test]
fn test_page_allocator_stats_default() {
    let stats = PageAllocatorStats {
        total_allocations: 0,
        total_deallocations: 0,
        active_pages: 0,
        bytes_allocated: 0,
        peak_pages: 0,
        allocated_pages: 0,
    };

    assert_eq!(stats.total_allocations, 0);
    assert_eq!(stats.total_deallocations, 0);
    assert_eq!(stats.active_pages, 0);
    assert_eq!(stats.bytes_allocated, 0);
    assert_eq!(stats.peak_pages, 0);
    assert_eq!(stats.allocated_pages, 0);
}

// ============================================================================
// PAGE INFO TESTS
// ============================================================================

#[test]
fn test_page_info_fields() {
    let info = PageInfo {
        page_id: 1,
        virtual_addr: VirtAddr::new(0x1000),
        physical_addr: PhysAddr::new(0x2000),
        allocation_time: 12345,
        size: 4096,
    };

    assert_eq!(info.page_id, 1);
    assert_eq!(info.virtual_addr.as_u64(), 0x1000);
    assert_eq!(info.physical_addr.as_u64(), 0x2000);
    assert_eq!(info.allocation_time, 12345);
    assert_eq!(info.size, 4096);
}

// ============================================================================
// ALLOCATOR STATS INTERNAL TESTS
// ============================================================================

#[test]
fn test_allocator_stats_new() {
    let stats = AllocatorStats::new();
    assert_eq!(stats.total_allocations.load(Ordering::Relaxed), 0);
    assert_eq!(stats.total_deallocations.load(Ordering::Relaxed), 0);
    assert_eq!(stats.active_pages.load(Ordering::Relaxed), 0);
    assert_eq!(stats.bytes_allocated.load(Ordering::Relaxed), 0);
    assert_eq!(stats.peak_pages.load(Ordering::Relaxed), 0);
}

#[test]
fn test_allocator_stats_record_allocation() {
    let stats = AllocatorStats::new();

    stats.record_allocation(4096);
    assert_eq!(stats.total_allocations.load(Ordering::Relaxed), 1);
    assert_eq!(stats.active_pages.load(Ordering::Relaxed), 1);
    assert_eq!(stats.bytes_allocated.load(Ordering::Relaxed), 4096);
    assert_eq!(stats.peak_pages.load(Ordering::Relaxed), 1);

    stats.record_allocation(8192);
    assert_eq!(stats.total_allocations.load(Ordering::Relaxed), 2);
    assert_eq!(stats.active_pages.load(Ordering::Relaxed), 2);
    assert_eq!(stats.bytes_allocated.load(Ordering::Relaxed), 12288);
    assert_eq!(stats.peak_pages.load(Ordering::Relaxed), 2);
}

#[test]
fn test_allocator_stats_record_deallocation() {
    let stats = AllocatorStats::new();

    stats.record_allocation(4096);
    stats.record_allocation(4096);
    stats.record_deallocation(4096);

    assert_eq!(stats.total_allocations.load(Ordering::Relaxed), 2);
    assert_eq!(stats.total_deallocations.load(Ordering::Relaxed), 1);
    assert_eq!(stats.active_pages.load(Ordering::Relaxed), 1);
    assert_eq!(stats.bytes_allocated.load(Ordering::Relaxed), 4096);
    assert_eq!(stats.peak_pages.load(Ordering::Relaxed), 2);
}

// ============================================================================
// PUBLIC API TESTS
// ============================================================================

#[test]
fn test_get_allocation_count_initial() {
    let count = get_allocation_count();
    assert!(count >= 0);
}

#[test]
fn test_get_total_bytes_allocated_initial() {
    let bytes = get_total_bytes_allocated();
    assert!(bytes >= 0);
}

#[test]
fn test_get_peak_pages_initial() {
    let peak = get_peak_pages();
    assert!(peak >= 0);
}

#[test]
fn test_get_stats() {
    let stats = get_stats();
    assert!(stats.total_allocations >= stats.total_deallocations);
}
