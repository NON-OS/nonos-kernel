// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors

use crate::memory::buddy_alloc::{
    AllocStats,
    MAX_ORDER, MIN_ORDER, FREE_LIST_COUNT,
    ALLOC_FLAG_ZERO, ALLOC_FLAG_DMA, ALLOC_FLAG_UNCACHED, ALLOC_FLAG_WRITE_COMBINE,
    ALLOC_FLAG_USER, ALLOC_FLAG_EXEC,
    order_to_size, size_to_order, buddy_address,
};

#[test]
fn test_max_order_constant() {
    assert_eq!(MAX_ORDER, 20);
}

#[test]
fn test_min_order_constant() {
    assert_eq!(MIN_ORDER, 12);
}

#[test]
fn test_free_list_count_constant() {
    assert_eq!(FREE_LIST_COUNT, MAX_ORDER - MIN_ORDER + 1);
    assert_eq!(FREE_LIST_COUNT, 9);
}

#[test]
fn test_alloc_flag_zero() {
    assert_eq!(ALLOC_FLAG_ZERO, 0x0001);
}

#[test]
fn test_alloc_flag_dma() {
    assert_eq!(ALLOC_FLAG_DMA, 0x0002);
}

#[test]
fn test_alloc_flag_uncached() {
    assert_eq!(ALLOC_FLAG_UNCACHED, 0x0004);
}

#[test]
fn test_alloc_flag_write_combine() {
    assert_eq!(ALLOC_FLAG_WRITE_COMBINE, 0x0008);
}

#[test]
fn test_alloc_flag_user() {
    assert_eq!(ALLOC_FLAG_USER, 0x0010);
}

#[test]
fn test_alloc_flag_exec() {
    assert_eq!(ALLOC_FLAG_EXEC, 0x0020);
}

#[test]
fn test_alloc_flags_unique() {
    let flags = [
        ALLOC_FLAG_ZERO,
        ALLOC_FLAG_DMA,
        ALLOC_FLAG_UNCACHED,
        ALLOC_FLAG_WRITE_COMBINE,
        ALLOC_FLAG_USER,
        ALLOC_FLAG_EXEC,
    ];
    for (i, f1) in flags.iter().enumerate() {
        for (j, f2) in flags.iter().enumerate() {
            if i != j {
                assert_ne!(f1, f2);
            }
        }
    }
}

#[test]
fn test_alloc_flags_powers_of_two() {
    assert!(ALLOC_FLAG_ZERO.is_power_of_two());
    assert!(ALLOC_FLAG_DMA.is_power_of_two());
    assert!(ALLOC_FLAG_UNCACHED.is_power_of_two());
    assert!(ALLOC_FLAG_WRITE_COMBINE.is_power_of_two());
    assert!(ALLOC_FLAG_USER.is_power_of_two());
    assert!(ALLOC_FLAG_EXEC.is_power_of_two());
}

#[test]
fn test_alloc_flags_combinable() {
    let combined = ALLOC_FLAG_ZERO | ALLOC_FLAG_DMA;
    assert_eq!(combined, 0x0003);
    assert!((combined & ALLOC_FLAG_ZERO) != 0);
    assert!((combined & ALLOC_FLAG_DMA) != 0);
    assert!((combined & ALLOC_FLAG_UNCACHED) == 0);
}

#[test]
fn test_order_to_size_min() {
    let size = order_to_size(MIN_ORDER);
    assert_eq!(size, 1 << MIN_ORDER);
    assert_eq!(size, 4096);
}

#[test]
fn test_order_to_size_max() {
    let size = order_to_size(MAX_ORDER);
    assert_eq!(size, 1 << MAX_ORDER);
}

#[test]
fn test_order_to_size_various() {
    assert_eq!(order_to_size(12), 4096);
    assert_eq!(order_to_size(13), 8192);
    assert_eq!(order_to_size(14), 16384);
    assert_eq!(order_to_size(15), 32768);
}

#[test]
fn test_order_to_size_zero() {
    assert_eq!(order_to_size(0), 1);
}

#[test]
fn test_size_to_order_exact() {
    assert_eq!(size_to_order(4096), 12);
    assert_eq!(size_to_order(8192), 13);
    assert_eq!(size_to_order(16384), 14);
}

#[test]
fn test_size_to_order_non_power_of_two() {
    assert_eq!(size_to_order(4097), 13);
    assert_eq!(size_to_order(5000), 13);
    assert_eq!(size_to_order(8193), 14);
}

#[test]
fn test_size_to_order_small() {
    assert_eq!(size_to_order(1), 0);
    assert_eq!(size_to_order(2), 1);
    assert_eq!(size_to_order(3), 2);
    assert_eq!(size_to_order(4), 2);
}

#[test]
fn test_size_to_order_large() {
    assert_eq!(size_to_order(1024 * 1024), 20);
}

#[test]
fn test_order_to_size_roundtrip() {
    for order in MIN_ORDER..=MAX_ORDER {
        let size = order_to_size(order);
        assert_eq!(size_to_order(size), order);
    }
}

#[test]
fn test_buddy_address_order_12() {
    let addr = 0x1000u64;
    let buddy = buddy_address(addr, 12);
    assert_eq!(buddy, 0x2000);
}

#[test]
fn test_buddy_address_order_13() {
    let addr = 0x2000u64;
    let buddy = buddy_address(addr, 13);
    assert_eq!(buddy, 0x0);
}

#[test]
fn test_buddy_address_xor_property() {
    let addr = 0x4000u64;
    let order = 14;
    let buddy = buddy_address(addr, order);
    assert_eq!(buddy_address(buddy, order), addr);
}

#[test]
fn test_buddy_address_different_orders() {
    let addr = 0x10000u64;
    let buddy12 = buddy_address(addr, 12);
    let buddy13 = buddy_address(addr, 13);
    let buddy14 = buddy_address(addr, 14);
    assert_ne!(buddy12, buddy13);
    assert_ne!(buddy13, buddy14);
}

#[test]
fn test_alloc_stats_new() {
    let stats = AllocStats::new();
    assert_eq!(stats.allocated, 0);
    assert_eq!(stats.peak, 0);
    assert_eq!(stats.active_ranges, 0);
    assert_eq!(stats.free_ranges, 0);
}

#[test]
fn test_alloc_stats_free_memory() {
    let stats = AllocStats {
        allocated: 100,
        peak: 200,
        active_ranges: 5,
        free_ranges: 10,
    };
    assert_eq!(stats.free_memory(1000), 900);
}

#[test]
fn test_alloc_stats_free_memory_zero_allocated() {
    let stats = AllocStats::new();
    assert_eq!(stats.free_memory(1000), 1000);
}

#[test]
fn test_alloc_stats_free_memory_full() {
    let stats = AllocStats {
        allocated: 1000,
        peak: 1000,
        active_ranges: 10,
        free_ranges: 0,
    };
    assert_eq!(stats.free_memory(1000), 0);
}

#[test]
fn test_alloc_stats_clone() {
    let stats = AllocStats {
        allocated: 50,
        peak: 100,
        active_ranges: 3,
        free_ranges: 7,
    };
    let cloned = stats.clone();
    assert_eq!(stats.allocated, cloned.allocated);
    assert_eq!(stats.peak, cloned.peak);
    assert_eq!(stats.active_ranges, cloned.active_ranges);
    assert_eq!(stats.free_ranges, cloned.free_ranges);
}

#[test]
fn test_alloc_stats_copy() {
    let stats1 = AllocStats {
        allocated: 25,
        peak: 50,
        active_ranges: 2,
        free_ranges: 4,
    };
    let stats2 = stats1;
    assert_eq!(stats1.allocated, stats2.allocated);
}

#[test]
fn test_alloc_stats_default() {
    let stats = AllocStats::default();
    assert_eq!(stats.allocated, 0);
    assert_eq!(stats.peak, 0);
}

#[test]
fn test_order_range_valid() {
    assert!(MIN_ORDER <= MAX_ORDER);
    for order in MIN_ORDER..=MAX_ORDER {
        let size = order_to_size(order);
        assert!(size.is_power_of_two());
    }
}

#[test]
fn test_buddy_address_aligned() {
    let base = 0x100000u64;
    for order in MIN_ORDER..=MAX_ORDER {
        let buddy = buddy_address(base, order);
        let block_size = 1u64 << order;
        assert_eq!(buddy % block_size, 0);
    }
}

#[test]
fn test_alloc_flags_all_combined() {
    let all = ALLOC_FLAG_ZERO | ALLOC_FLAG_DMA | ALLOC_FLAG_UNCACHED |
              ALLOC_FLAG_WRITE_COMBINE | ALLOC_FLAG_USER | ALLOC_FLAG_EXEC;
    assert_eq!(all, 0x003F);
}

#[test]
fn test_order_to_size_powers_of_two() {
    for order in 0..=MAX_ORDER {
        let size = order_to_size(order);
        assert!(size.is_power_of_two());
    }
}

#[test]
fn test_size_to_order_zero() {
    assert_eq!(size_to_order(0), 0);
}

#[test]
fn test_buddy_address_zero() {
    let buddy = buddy_address(0, 12);
    assert_eq!(buddy, 0x1000);
}

#[test]
fn test_alloc_stats_fields_modification() {
    let mut stats = AllocStats::new();
    stats.allocated = 100;
    stats.peak = 200;
    stats.active_ranges = 5;
    stats.free_ranges = 10;
    assert_eq!(stats.allocated, 100);
    assert_eq!(stats.peak, 200);
    assert_eq!(stats.active_ranges, 5);
    assert_eq!(stats.free_ranges, 10);
}

#[test]
fn test_order_boundaries() {
    let min_size = order_to_size(MIN_ORDER);
    let max_size = order_to_size(MAX_ORDER);
    assert_eq!(min_size, 4096);
    assert!(max_size > min_size);
}

#[test]
fn test_buddy_address_large() {
    let addr = 0x1_0000_0000u64;
    let buddy = buddy_address(addr, 12);
    assert_ne!(buddy, addr);
}

#[test]
fn test_alloc_stats_utilization() {
    let stats = AllocStats {
        allocated: 500,
        peak: 1000,
        active_ranges: 10,
        free_ranges: 20,
    };
    let total = 1000u64;
    let free = stats.free_memory(total);
    assert_eq!(free, 500);
    let utilization = (stats.allocated * 100) / total;
    assert_eq!(utilization, 50);
}

#[test]
fn test_flag_isolation() {
    let flags = ALLOC_FLAG_ZERO | ALLOC_FLAG_USER;
    assert!((flags & ALLOC_FLAG_ZERO) != 0);
    assert!((flags & ALLOC_FLAG_USER) != 0);
    assert!((flags & ALLOC_FLAG_DMA) == 0);
    assert!((flags & ALLOC_FLAG_EXEC) == 0);
}

#[test]
fn test_order_to_size_consistency() {
    let size1 = order_to_size(12);
    let size2 = order_to_size(13);
    assert_eq!(size2, size1 * 2);
}

#[test]
fn test_buddy_pairs() {
    for order in MIN_ORDER..MAX_ORDER {
        let addr = 0u64;
        let buddy = buddy_address(addr, order);
        let original = buddy_address(buddy, order);
        assert_eq!(original, addr);
    }
}

