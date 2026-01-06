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
use super::error::HeapError;
// ============================================================================
// CONSTANTS TESTS
// ============================================================================

#[test]
fn test_allocation_magic() {
    assert_eq!(ALLOCATION_MAGIC, 0xDEADBEEF);
}

#[test]
fn test_canary_value() {
    assert_eq!(CANARY_VALUE, 0xDEADBEEFCAFEBABE);
}

#[test]
fn test_freed_magic() {
    assert_eq!(FREED_MAGIC, 0xFEEDFACE);
    assert_ne!(FREED_MAGIC, ALLOCATION_MAGIC);
}

#[test]
fn test_bootstrap_heap_size() {
    assert_eq!(BOOTSTRAP_HEAP_SIZE, 1024 * 1024); // 1 MiB
}

#[test]
fn test_alignment_constants() {
    assert_eq!(MIN_ALIGNMENT, 8);
    assert_eq!(MAX_ALIGNMENT, 4096);
    assert_eq!(DEFAULT_ALIGNMENT, 16);
    assert!(MIN_ALIGNMENT <= DEFAULT_ALIGNMENT);
    assert!(DEFAULT_ALIGNMENT <= MAX_ALIGNMENT);
}

#[test]
fn test_size_limits() {
    assert_eq!(MIN_ALLOCATION_SIZE, 8);
    assert_eq!(MAX_ALLOCATION_SIZE, 256 * 1024 * 1024);
    assert_eq!(LARGE_ALLOCATION_THRESHOLD, 64 * 1024);
}

#[test]
fn test_header_sizes() {
    assert_eq!(ALLOCATION_HEADER_SIZE, 24);
    assert_eq!(CANARY_SIZE, 8);
    assert_eq!(ALLOCATION_OVERHEAD, ALLOCATION_HEADER_SIZE + CANARY_SIZE);
}

#[test]
fn test_security_patterns() {
    assert_eq!(FREED_MEMORY_PATTERN, 0xDD);
    assert_eq!(FRESH_MEMORY_PATTERN, 0xCD);
    assert_eq!(GUARD_PAGE_PATTERN, 0xFD);
    // Patterns should be distinct
    assert_ne!(FREED_MEMORY_PATTERN, FRESH_MEMORY_PATTERN);
    assert_ne!(FREED_MEMORY_PATTERN, GUARD_PAGE_PATTERN);
    assert_ne!(FRESH_MEMORY_PATTERN, GUARD_PAGE_PATTERN);
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_error_display() {
    assert_eq!(HeapError::NotInitialized.as_str(), "Heap not initialized");
    assert_eq!(HeapError::OutOfMemory.as_str(), "Out of memory");
    assert_eq!(HeapError::DoubleFree.as_str(), "Double free detected");
    assert_eq!(HeapError::HeapCorruption.as_str(), "Heap corruption detected");
    assert_eq!(HeapError::BufferOverflow.as_str(), "Buffer overflow detected");
}

#[test]
fn test_error_is_security_critical() {
    assert!(HeapError::DoubleFree.is_security_critical());
    assert!(HeapError::HeapCorruption.is_security_critical());
    assert!(HeapError::BufferOverflow.is_security_critical());
    assert!(HeapError::InvalidPointer.is_security_critical());
    assert!(HeapError::PointerOutOfRange.is_security_critical());

    assert!(!HeapError::NotInitialized.is_security_critical());
    assert!(!HeapError::OutOfMemory.is_security_critical());
    assert!(!HeapError::AllocationTooLarge.is_security_critical());
}

#[test]
fn test_error_indicates_corruption() {
    assert!(HeapError::HeapCorruption.indicates_corruption());
    assert!(HeapError::BufferOverflow.indicates_corruption());
    assert!(HeapError::SizeMismatch.indicates_corruption());
    assert!(HeapError::IntegrityCheckFailed.indicates_corruption());

    assert!(!HeapError::DoubleFree.indicates_corruption());
    assert!(!HeapError::OutOfMemory.indicates_corruption());
}

#[test]
fn test_error_from_string() {
    let err: HeapError = "Failed to allocate heap frames".into();
    assert_eq!(err, HeapError::FrameAllocationFailed);

    let err: HeapError = "Failed to map heap page".into();
    assert_eq!(err, HeapError::MappingFailed);
}

// ============================================================================
// ALLOCATION HEADER TESTS
// ============================================================================

#[test]
fn test_allocation_header_new() {
    let header = AllocationHeader::new(100, 12345);
    assert_eq!(header.magic, ALLOCATION_MAGIC);
    assert_eq!(header.size, 100);
    assert_eq!(header.canary_offset, 100);
    assert_eq!(header.allocated_at, 12345);
}

#[test]
fn test_allocation_header_is_valid() {
    let valid_header = AllocationHeader::new(100, 0);
    assert!(valid_header.is_valid());

    let invalid_header = AllocationHeader {
        magic: 0x12345678,
        size: 100,
        canary_offset: 100,
        allocated_at: 0,
    };
    assert!(!invalid_header.is_valid());
}

// ============================================================================
// HEAP STATS TESTS
// ============================================================================

#[test]
fn test_heap_stats_free_memory() {
    let stats = HeapStats {
        total_size: 1000,
        current_usage: 300,
        peak_usage: 500,
        allocation_count: 10,
    };
    assert_eq!(stats.free_memory(), 700);

    let full_stats = HeapStats {
        total_size: 1000,
        current_usage: 1000,
        peak_usage: 1000,
        allocation_count: 100,
    };
    assert_eq!(full_stats.free_memory(), 0);

    let over_stats = HeapStats {
        total_size: 100,
        current_usage: 200,
        peak_usage: 200,
        allocation_count: 10,
    };
    assert_eq!(over_stats.free_memory(), 0);
}

#[test]
fn test_heap_stats_usage_percent() {
    let half_used = HeapStats {
        total_size: 1000,
        current_usage: 500,
        peak_usage: 500,
        allocation_count: 10,
    };
    assert!((half_used.usage_percent() - 50.0).abs() < 0.01);

    let empty = HeapStats {
        total_size: 0,
        current_usage: 0,
        peak_usage: 0,
        allocation_count: 0,
    };
    assert_eq!(empty.usage_percent(), 0.0);
}

// ============================================================================
// HEAP STATISTICS INTERNAL TESTS
// ============================================================================

#[test]
fn test_heap_statistics_new() {
    let stats = HeapStatistics::new();
    assert_eq!(stats.total_size.load(Ordering::Relaxed), 0);
    assert_eq!(stats.current_usage.load(Ordering::Relaxed), 0);
    assert_eq!(stats.peak_usage.load(Ordering::Relaxed), 0);
    assert_eq!(stats.allocation_count.load(Ordering::Relaxed), 0);
    assert_eq!(stats.deallocation_count.load(Ordering::Relaxed), 0);
}

#[test]
fn test_heap_statistics_record_allocation() {
    let stats = HeapStatistics::new();

    stats.record_allocation(100);
    assert_eq!(stats.current_usage.load(Ordering::Relaxed), 100);
    assert_eq!(stats.allocation_count.load(Ordering::Relaxed), 1);
    assert_eq!(stats.peak_usage.load(Ordering::Relaxed), 100);

    stats.record_allocation(50);
    assert_eq!(stats.current_usage.load(Ordering::Relaxed), 150);
    assert_eq!(stats.allocation_count.load(Ordering::Relaxed), 2);
    assert_eq!(stats.peak_usage.load(Ordering::Relaxed), 150);
}

#[test]
fn test_heap_statistics_record_deallocation() {
    let stats = HeapStatistics::new();

    stats.record_allocation(100);
    stats.record_deallocation(50);

    assert_eq!(stats.current_usage.load(Ordering::Relaxed), 50);
    assert_eq!(stats.deallocation_count.load(Ordering::Relaxed), 1);
    // Peak should remain at previous high
    assert_eq!(stats.peak_usage.load(Ordering::Relaxed), 100);
}

#[test]
fn test_heap_statistics_peak_tracking() {
    let stats = HeapStatistics::new();

    stats.record_allocation(100);
    stats.record_allocation(200);
    assert_eq!(stats.peak_usage.load(Ordering::Relaxed), 300);

    stats.record_deallocation(200);
    stats.record_allocation(50);
    // Peak should still be 300, not reset to 150
    assert_eq!(stats.peak_usage.load(Ordering::Relaxed), 300);
}

#[test]
fn test_heap_statistics_set_total_size() {
    let stats = HeapStatistics::new();

    stats.set_total_size(1024 * 1024);
    assert_eq!(stats.total_size.load(Ordering::Relaxed), 1024 * 1024);
}

#[test]
fn test_heap_statistics_get_stats() {
    let stats = HeapStatistics::new();
    stats.set_total_size(1000);
    stats.record_allocation(100);
    stats.record_allocation(50);
    stats.record_deallocation(50);

    let heap_stats = stats.get_stats();
    assert_eq!(heap_stats.total_size, 1000);
    assert_eq!(heap_stats.current_usage, 100);
    assert_eq!(heap_stats.peak_usage, 150);
    assert_eq!(heap_stats.allocation_count, 2);
}

// ============================================================================
// PUBLIC API TESTS
// ============================================================================

#[test]
fn test_is_using_bootstrap_initial() {
    // Should be true initially
    let _ = is_using_bootstrap();
}

#[test]
fn test_get_heap_stats_runs() {
    let _ = get_heap_stats();
}

#[test]
fn test_init_returns_ok() {
    assert!(init().is_ok());
}

#[test]
fn test_verify_heap_integrity_runs() {
    assert!(verify_heap_integrity());
}

// ============================================================================
// ZERO ON ALLOC/FREE TESTS
// ============================================================================

#[test]
fn test_set_heap_zero_on_alloc() {
    set_heap_zero_on_alloc(true);
    assert!(HEAP_ZERO_ON_ALLOC.load(Ordering::Relaxed));

    set_heap_zero_on_alloc(false);
    assert!(!HEAP_ZERO_ON_ALLOC.load(Ordering::Relaxed));

    // Reset to default
    set_heap_zero_on_alloc(true);
}

#[test]
fn test_set_heap_zero_on_free() {
    set_heap_zero_on_free(true);
    assert!(HEAP_ZERO_ON_FREE.load(Ordering::Relaxed));

    set_heap_zero_on_free(false);
    assert!(!HEAP_ZERO_ON_FREE.load(Ordering::Relaxed));

    // Reset to default
    set_heap_zero_on_free(true);
}

// ============================================================================
// SECURE HEAP ALLOCATOR TESTS
// ============================================================================

#[test]
fn test_secure_heap_allocator_new() {
    let allocator = SecureHeapAllocator::new();
    assert!(!allocator.is_initialized());
    assert_eq!(allocator.get_heap_size(), 0);
    assert_eq!(allocator.canary_value, CANARY_VALUE);
}

#[test]
fn test_secure_heap_allocator_is_initialized() {
    let allocator = SecureHeapAllocator::new();
    assert!(!allocator.is_initialized());
}
