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
#[test]
fn test_order_constants() {
    assert_eq!(MIN_ORDER, 12);
    assert_eq!(MAX_ORDER, 20);
    assert_eq!(FREE_LIST_COUNT, 9);
    assert_eq!(MIN_BLOCK_SIZE, 4096);
    assert_eq!(MAX_BLOCK_SIZE, 1 << 20);
}

#[test]
fn test_page_size() {
    assert_eq!(PAGE_SIZE, 4096);
    assert_eq!(PAGE_SIZE_U64, 4096u64);
    assert_eq!(MIN_BLOCK_SIZE, PAGE_SIZE);
}

#[test]
fn test_alignment_constants() {
    assert_eq!(MIN_ALIGNMENT, PAGE_SIZE);
    assert_eq!(MAX_ALIGNMENT, MAX_BLOCK_SIZE);
}

#[test]
fn test_allocation_flags() {
    assert_eq!(ALLOC_FLAG_ZERO, 0x0001);
    assert_eq!(ALLOC_FLAG_DMA, 0x0002);
    assert_eq!(ALLOC_FLAG_UNCACHED, 0x0004);
    assert_eq!(ALLOC_FLAG_WRITE_COMBINE, 0x0008);
    assert_eq!(ALLOC_FLAG_USER, 0x0010);
    assert_eq!(ALLOC_FLAG_EXEC, 0x0020);
}

// ============================================================================
// ORDER CALCULATION TESTS
// ============================================================================

#[test]
fn test_order_to_size() {
    assert_eq!(order_to_size(12), 4096);
    assert_eq!(order_to_size(13), 8192);
    assert_eq!(order_to_size(14), 16384);
    assert_eq!(order_to_size(20), 1 << 20);
}

#[test]
fn test_size_to_order() {
    // Exact sizes
    assert_eq!(size_to_order(4096), 12);
    assert_eq!(size_to_order(8192), 13);
    assert_eq!(size_to_order(1 << 20), 20);

    // Round up
    assert_eq!(size_to_order(4097), 13);
    assert_eq!(size_to_order(5000), 13);
    assert_eq!(size_to_order(8193), 14);

    // Below minimum
    assert_eq!(size_to_order(1), 12);
    assert_eq!(size_to_order(100), 12);
    assert_eq!(size_to_order(4095), 12);
}

#[test]
fn test_buddy_address() {
    // Order 12 (4 KiB blocks)
    assert_eq!(buddy_address(0x1000, 12), 0x0000);
    assert_eq!(buddy_address(0x0000, 12), 0x1000);

    // Order 13 (8 KiB blocks)
    assert_eq!(buddy_address(0x2000, 13), 0x0000);
    assert_eq!(buddy_address(0x0000, 13), 0x2000);

    // Order 14 (16 KiB blocks)
    assert_eq!(buddy_address(0x4000, 14), 0x0000);
    assert_eq!(buddy_address(0x0000, 14), 0x4000);
}

#[test]
fn test_buddy_address_xor_property() {
    // buddy(buddy(addr)) == addr
    for order in MIN_ORDER..=MAX_ORDER {
        let addr = 0x10000u64;
        let buddy = buddy_address(addr, order);
        let back = buddy_address(buddy, order);
        assert_eq!(back, addr, "XOR property failed for order {}", order);
    }
}

// ============================================================================
// ALIGN_UP TESTS
// ============================================================================

#[test]
fn test_align_up_exact() {
    assert_eq!(align_up(4096, 4096), 4096);
    assert_eq!(align_up(8192, 4096), 8192);
}

#[test]
fn test_align_up_round() {
    assert_eq!(align_up(4097, 4096), 8192);
    assert_eq!(align_up(1, 4096), 4096);
    assert_eq!(align_up(4095, 4096), 4096);
}

#[test]
fn test_align_up_invalid() {
    // Zero alignment returns value unchanged
    assert_eq!(align_up(100, 0), 100);

    // Non-power-of-two returns value unchanged
    assert_eq!(align_up(100, 3), 100);
    assert_eq!(align_up(100, 5), 100);
}

// ============================================================================
// TYPE TESTS
// ============================================================================

#[test]
fn test_buddy_block_creation() {
    let block = BuddyBlock {
        addr: 0x1000,
        order: 12,
    };
    assert_eq!(block.addr, 0x1000);
    assert_eq!(block.order, 12);
}

#[test]
fn test_allocated_block_creation() {
    let block = AllocatedBlock {
        addr: 0x1000,
        size: 4096,
        order: 12,
        flags: ALLOC_FLAG_ZERO,
    };
    assert_eq!(block.addr, 0x1000);
    assert_eq!(block.size, 4096);
    assert_eq!(block.order, 12);
    assert_eq!(block.flags, ALLOC_FLAG_ZERO);
}

#[test]
fn test_alloc_stats_default() {
    let stats = AllocStats::new();
    assert_eq!(stats.total_allocated, 0);
    assert_eq!(stats.peak_allocated, 0);
    assert_eq!(stats.allocation_count, 0);
    assert_eq!(stats.free_count, 0);
    assert_eq!(stats.active_ranges, 0);
}

#[test]
fn test_alloc_stats_free_memory() {
    let stats = AllocStats {
        total_allocated: 1000,
        peak_allocated: 2000,
        allocation_count: 5,
        free_count: 2,
        active_ranges: 3,
    };
    assert_eq!(stats.free_memory(5000), 4000);
    assert_eq!(stats.free_memory(1000), 0);
    assert_eq!(stats.free_memory(500), 0); // Can't be negative
}

// ============================================================================
// ERROR TESTS
// ============================================================================

#[test]
fn test_error_as_str() {
    assert_eq!(
        BuddyAllocError::NotInitialized.as_str(),
        "Allocator not initialized"
    );
    assert_eq!(
        BuddyAllocError::InvalidSize.as_str(),
        "Invalid allocation size"
    );
    assert_eq!(
        BuddyAllocError::OutOfVirtualMemory.as_str(),
        "Out of virtual memory"
    );
}

#[test]
fn test_error_is_fatal() {
    assert!(BuddyAllocError::OutOfVirtualMemory.is_fatal());
    assert!(BuddyAllocError::FrameAllocationFailed.is_fatal());
    assert!(!BuddyAllocError::InvalidSize.is_fatal());
    assert!(!BuddyAllocError::NotInitialized.is_fatal());
}

#[test]
fn test_error_indicates_corruption() {
    assert!(BuddyAllocError::InvalidAddress.indicates_corruption());
    assert!(BuddyAllocError::DoubleFree.indicates_corruption());
    assert!(BuddyAllocError::BlockOutOfRange.indicates_corruption());
    assert!(!BuddyAllocError::InvalidSize.indicates_corruption());
}

#[test]
fn test_error_display() {
    let error = BuddyAllocError::InvalidAlignment;
    let msg = format!("{}", error);
    assert_eq!(msg, "Invalid alignment (must be power of two)");
}

#[test]
fn test_error_from_str() {
    assert_eq!(
        BuddyAllocError::from("Allocator not initialized"),
        BuddyAllocError::NotInitialized
    );
    assert_eq!(
        BuddyAllocError::from("Invalid allocation size"),
        BuddyAllocError::InvalidSize
    );
    assert_eq!(
        BuddyAllocError::from("Out of virtual memory"),
        BuddyAllocError::OutOfVirtualMemory
    );
}

// ============================================================================
// ALLOCATOR UNIT TESTS
// ============================================================================

#[test]
fn test_allocator_creation() {
    let allocator = VmapAllocator::new();
    assert!(!allocator.is_allocated(0x1000));
}

#[test]
fn test_free_list_count() {
    // Orders 12, 13, 14, 15, 16, 17, 18, 19, 20 = 9 lists
    assert_eq!(FREE_LIST_COUNT, 9);
}

// ============================================================================
// STATISTICS TESTS
// ============================================================================

#[test]
fn test_allocation_statistics_new() {
    let stats = AllocationStatistics::new();
    assert_eq!(stats.total_allocated(), 0);
    assert_eq!(stats.peak_allocated(), 0);
    assert_eq!(stats.allocation_count(), 0);
    assert_eq!(stats.free_count(), 0);
}

#[test]
fn test_allocation_statistics_record() {
    let stats = AllocationStatistics::new();
    stats.record_allocation(1000);
    assert_eq!(stats.total_allocated(), 1000);
    assert_eq!(stats.peak_allocated(), 1000);
    assert_eq!(stats.allocation_count(), 1);
    stats.record_allocation(500);
    assert_eq!(stats.total_allocated(), 1500);
    assert_eq!(stats.peak_allocated(), 1500);
    assert_eq!(stats.allocation_count(), 2);
    stats.record_deallocation(500);
    assert_eq!(stats.total_allocated(), 1000);
    assert_eq!(stats.peak_allocated(), 1500); // Peak unchanged
    assert_eq!(stats.free_count(), 1);
}

#[test]
fn test_allocation_statistics_peak_tracking() {
    let stats = AllocationStatistics::new();
    stats.record_allocation(1000);
    stats.record_deallocation(1000);
    stats.record_allocation(500);
    assert_eq!(stats.total_allocated(), 500);
    assert_eq!(stats.peak_allocated(), 1000); // Peak remains at previous high
}

#[test]
fn test_allocation_statistics_get_stats() {
    let stats = AllocationStatistics::new();
    stats.record_allocation(4096);
    stats.record_allocation(8192);
    stats.record_deallocation(4096);
    let snapshot = stats.get_stats(5);
    assert_eq!(snapshot.total_allocated, 8192);
    assert_eq!(snapshot.peak_allocated, 4096 + 8192);
    assert_eq!(snapshot.allocation_count, 2);
    assert_eq!(snapshot.free_count, 1);
    assert_eq!(snapshot.active_ranges, 5);
}

// ============================================================================
// EDGE CASE TESTS
// ============================================================================
#[test]
fn test_order_edge_cases() {
    assert_eq!(size_to_order(0), MIN_ORDER);
    assert_eq!(size_to_order(1), MIN_ORDER);
    assert_eq!(size_to_order(MIN_BLOCK_SIZE), MIN_ORDER);
    assert_eq!(size_to_order(MIN_BLOCK_SIZE + 1), MIN_ORDER + 1);
}

#[test]
fn test_buddy_at_region_boundaries() {
    let buddy = buddy_address(0, MIN_ORDER);
    assert_eq!(buddy, MIN_BLOCK_SIZE as u64);

    // XOR should work at any address
    let addr = 0xFFFF_0000u64;
    let buddy = buddy_address(addr, MIN_ORDER);
    let back = buddy_address(buddy, MIN_ORDER);
    assert_eq!(back, addr);
}

#[test]
fn test_flags_are_independent() {
    let flags = ALLOC_FLAG_ZERO | ALLOC_FLAG_DMA;
    assert_eq!(flags, 0x0003);
    assert!(flags & ALLOC_FLAG_ZERO != 0);
    assert!(flags & ALLOC_FLAG_DMA != 0);
    assert!(flags & ALLOC_FLAG_UNCACHED == 0);
}
