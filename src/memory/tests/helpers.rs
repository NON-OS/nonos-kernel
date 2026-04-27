// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
//
// Buddy allocator helper tests

use crate::memory::buddy_alloc::{
    buddy_address, order_to_size, size_to_order, AllocStats, ALLOC_FLAG_DMA, ALLOC_FLAG_EXEC,
    ALLOC_FLAG_UNCACHED, ALLOC_FLAG_USER, ALLOC_FLAG_WRITE_COMBINE, ALLOC_FLAG_ZERO,
    FREE_LIST_COUNT, MAX_ORDER, MIN_ORDER,
};
use crate::test::framework::TestResult;

pub(crate) fn test_max_order_constant() -> TestResult {
    if MAX_ORDER != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_min_order_constant() -> TestResult {
    if MIN_ORDER != 12 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_free_list_count_constant() -> TestResult {
    if FREE_LIST_COUNT != MAX_ORDER - MIN_ORDER + 1 {
        return TestResult::Fail;
    }
    if FREE_LIST_COUNT != 9 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flag_zero() -> TestResult {
    if ALLOC_FLAG_ZERO != 0x0001 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flag_dma() -> TestResult {
    if ALLOC_FLAG_DMA != 0x0002 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flag_uncached() -> TestResult {
    if ALLOC_FLAG_UNCACHED != 0x0004 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flag_write_combine() -> TestResult {
    if ALLOC_FLAG_WRITE_COMBINE != 0x0008 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flag_user() -> TestResult {
    if ALLOC_FLAG_USER != 0x0010 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flag_exec() -> TestResult {
    if ALLOC_FLAG_EXEC != 0x0020 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_unique() -> TestResult {
    let flags = [
        ALLOC_FLAG_ZERO,
        ALLOC_FLAG_DMA,
        ALLOC_FLAG_UNCACHED,
        ALLOC_FLAG_WRITE_COMBINE,
        ALLOC_FLAG_USER,
        ALLOC_FLAG_EXEC,
    ];
    for i in 0..flags.len() {
        for j in 0..flags.len() {
            if i != j && flags[i] == flags[j] {
                return TestResult::Fail;
            }
        }
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_powers_of_two() -> TestResult {
    if !ALLOC_FLAG_ZERO.is_power_of_two() {
        return TestResult::Fail;
    }
    if !ALLOC_FLAG_DMA.is_power_of_two() {
        return TestResult::Fail;
    }
    if !ALLOC_FLAG_UNCACHED.is_power_of_two() {
        return TestResult::Fail;
    }
    if !ALLOC_FLAG_WRITE_COMBINE.is_power_of_two() {
        return TestResult::Fail;
    }
    if !ALLOC_FLAG_USER.is_power_of_two() {
        return TestResult::Fail;
    }
    if !ALLOC_FLAG_EXEC.is_power_of_two() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_combinable() -> TestResult {
    let combined = ALLOC_FLAG_ZERO | ALLOC_FLAG_DMA;
    if combined != 0x0003 {
        return TestResult::Fail;
    }
    if (combined & ALLOC_FLAG_ZERO) == 0 {
        return TestResult::Fail;
    }
    if (combined & ALLOC_FLAG_DMA) == 0 {
        return TestResult::Fail;
    }
    if (combined & ALLOC_FLAG_UNCACHED) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_to_size_min() -> TestResult {
    let size = order_to_size(MIN_ORDER);
    if size != 1 << MIN_ORDER {
        return TestResult::Fail;
    }
    if size != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_to_size_max() -> TestResult {
    let size = order_to_size(MAX_ORDER);
    if size != 1 << MAX_ORDER {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_to_size_various() -> TestResult {
    if order_to_size(12) != 4096 {
        return TestResult::Fail;
    }
    if order_to_size(13) != 8192 {
        return TestResult::Fail;
    }
    if order_to_size(14) != 16384 {
        return TestResult::Fail;
    }
    if order_to_size(15) != 32768 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_to_size_zero() -> TestResult {
    if order_to_size(0) != 1 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_size_to_order_exact() -> TestResult {
    if size_to_order(4096) != 12 {
        return TestResult::Fail;
    }
    if size_to_order(8192) != 13 {
        return TestResult::Fail;
    }
    if size_to_order(16384) != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_size_to_order_non_power_of_two() -> TestResult {
    if size_to_order(4097) != 13 {
        return TestResult::Fail;
    }
    if size_to_order(5000) != 13 {
        return TestResult::Fail;
    }
    if size_to_order(8193) != 14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_size_to_order_small() -> TestResult {
    if size_to_order(1) != 0 {
        return TestResult::Fail;
    }
    if size_to_order(2) != 1 {
        return TestResult::Fail;
    }
    if size_to_order(3) != 2 {
        return TestResult::Fail;
    }
    if size_to_order(4) != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_size_to_order_large() -> TestResult {
    if size_to_order(1024 * 1024) != 20 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_to_size_roundtrip() -> TestResult {
    for order in MIN_ORDER..=MAX_ORDER {
        let size = order_to_size(order);
        if size_to_order(size) != order {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_buddy_address_order_12() -> TestResult {
    let addr = 0x1000u64;
    let buddy = buddy_address(addr, 12);
    if buddy != 0x2000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buddy_address_order_13() -> TestResult {
    let addr = 0x2000u64;
    let buddy = buddy_address(addr, 13);
    if buddy != 0x0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buddy_address_xor_property() -> TestResult {
    let addr = 0x4000u64;
    let order = 14;
    let buddy = buddy_address(addr, order);
    if buddy_address(buddy, order) != addr {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buddy_address_different_orders() -> TestResult {
    let addr = 0x10000u64;
    let buddy12 = buddy_address(addr, 12);
    let buddy13 = buddy_address(addr, 13);
    let buddy14 = buddy_address(addr, 14);
    if buddy12 == buddy13 {
        return TestResult::Fail;
    }
    if buddy13 == buddy14 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_new() -> TestResult {
    let stats = AllocStats::new();
    if stats.allocated != 0 {
        return TestResult::Fail;
    }
    if stats.peak != 0 {
        return TestResult::Fail;
    }
    if stats.active_ranges != 0 {
        return TestResult::Fail;
    }
    if stats.free_ranges != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_free_memory() -> TestResult {
    let stats = AllocStats { allocated: 100, peak: 200, active_ranges: 5, free_ranges: 10 };
    if stats.free_memory(1000) != 900 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_free_memory_zero_allocated() -> TestResult {
    let stats = AllocStats::new();
    if stats.free_memory(1000) != 1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_free_memory_full() -> TestResult {
    let stats = AllocStats { allocated: 1000, peak: 1000, active_ranges: 10, free_ranges: 0 };
    if stats.free_memory(1000) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_clone() -> TestResult {
    let stats = AllocStats { allocated: 50, peak: 100, active_ranges: 3, free_ranges: 7 };
    let cloned = stats.clone();
    if stats.allocated != cloned.allocated {
        return TestResult::Fail;
    }
    if stats.peak != cloned.peak {
        return TestResult::Fail;
    }
    if stats.active_ranges != cloned.active_ranges {
        return TestResult::Fail;
    }
    if stats.free_ranges != cloned.free_ranges {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_copy() -> TestResult {
    let stats1 = AllocStats { allocated: 25, peak: 50, active_ranges: 2, free_ranges: 4 };
    let stats2 = stats1;
    if stats1.allocated != stats2.allocated {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_default() -> TestResult {
    let stats = AllocStats::default();
    if stats.allocated != 0 {
        return TestResult::Fail;
    }
    if stats.peak != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_range_valid() -> TestResult {
    if MIN_ORDER > MAX_ORDER {
        return TestResult::Fail;
    }
    for order in MIN_ORDER..=MAX_ORDER {
        let size = order_to_size(order);
        if !size.is_power_of_two() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_buddy_address_aligned() -> TestResult {
    let base = 0x100000u64;
    for order in MIN_ORDER..=MAX_ORDER {
        let buddy = buddy_address(base, order);
        let block_size = 1u64 << order;
        if buddy % block_size != 0 {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_flags_all_combined() -> TestResult {
    let all = ALLOC_FLAG_ZERO
        | ALLOC_FLAG_DMA
        | ALLOC_FLAG_UNCACHED
        | ALLOC_FLAG_WRITE_COMBINE
        | ALLOC_FLAG_USER
        | ALLOC_FLAG_EXEC;
    if all != 0x003F {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_to_size_powers_of_two() -> TestResult {
    for order in 0..=MAX_ORDER {
        let size = order_to_size(order);
        if !size.is_power_of_two() {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}

pub(crate) fn test_size_to_order_zero() -> TestResult {
    if size_to_order(0) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buddy_address_zero() -> TestResult {
    let buddy = buddy_address(0, 12);
    if buddy != 0x1000 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_fields_modification() -> TestResult {
    let mut stats = AllocStats::new();
    stats.allocated = 100;
    stats.peak = 200;
    stats.active_ranges = 5;
    stats.free_ranges = 10;
    if stats.allocated != 100 {
        return TestResult::Fail;
    }
    if stats.peak != 200 {
        return TestResult::Fail;
    }
    if stats.active_ranges != 5 {
        return TestResult::Fail;
    }
    if stats.free_ranges != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_boundaries() -> TestResult {
    let min_size = order_to_size(MIN_ORDER);
    let max_size = order_to_size(MAX_ORDER);
    if min_size != 4096 {
        return TestResult::Fail;
    }
    if max_size <= min_size {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buddy_address_large() -> TestResult {
    let addr = 0x1_0000_0000u64;
    let buddy = buddy_address(addr, 12);
    if buddy == addr {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_alloc_stats_utilization() -> TestResult {
    let stats = AllocStats { allocated: 500, peak: 1000, active_ranges: 10, free_ranges: 20 };
    let total = 1000u64;
    let free = stats.free_memory(total);
    if free != 500 {
        return TestResult::Fail;
    }
    let utilization = (stats.allocated * 100) / total;
    if utilization != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_flag_isolation() -> TestResult {
    let flags = ALLOC_FLAG_ZERO | ALLOC_FLAG_USER;
    if (flags & ALLOC_FLAG_ZERO) == 0 {
        return TestResult::Fail;
    }
    if (flags & ALLOC_FLAG_USER) == 0 {
        return TestResult::Fail;
    }
    if (flags & ALLOC_FLAG_DMA) != 0 {
        return TestResult::Fail;
    }
    if (flags & ALLOC_FLAG_EXEC) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_order_to_size_consistency() -> TestResult {
    let size1 = order_to_size(12);
    let size2 = order_to_size(13);
    if size2 != size1 * 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_buddy_pairs() -> TestResult {
    for order in MIN_ORDER..MAX_ORDER {
        let addr = 0u64;
        let buddy = buddy_address(addr, order);
        let original = buddy_address(buddy, order);
        if original != addr {
            return TestResult::Fail;
        }
    }
    TestResult::Pass
}
