use crate::npkg::*;
use crate::npkg::cache::{CachePolicy, CacheStats};

#[test]
fn test_cache_policy_default() {
    let policy: CachePolicy = Default::default();
    assert_eq!(policy, CachePolicy::KeepLatest);
}

#[test]
fn test_cache_policy_variants() {
    let policies = [
        CachePolicy::KeepAll,
        CachePolicy::KeepLatest,
        CachePolicy::KeepInstalled,
        CachePolicy::KeepNone,
    ];
    assert_eq!(policies.len(), 4);
}

#[test]
fn test_cache_policy_equality() {
    assert_eq!(CachePolicy::KeepAll, CachePolicy::KeepAll);
    assert_eq!(CachePolicy::KeepLatest, CachePolicy::KeepLatest);
    assert_eq!(CachePolicy::KeepInstalled, CachePolicy::KeepInstalled);
    assert_eq!(CachePolicy::KeepNone, CachePolicy::KeepNone);
}

#[test]
fn test_cache_policy_inequality() {
    assert_ne!(CachePolicy::KeepAll, CachePolicy::KeepNone);
    assert_ne!(CachePolicy::KeepLatest, CachePolicy::KeepInstalled);
}

#[test]
fn test_cache_policy_copy() {
    let policy = CachePolicy::KeepAll;
    let copied = policy;
    assert_eq!(policy, copied);
}

#[test]
fn test_cache_policy_clone() {
    let policy = CachePolicy::KeepLatest;
    let cloned = policy.clone();
    assert_eq!(policy, cloned);
}

#[test]
fn test_cache_stats_structure() {
    let stats = CacheStats {
        total_size: 1024 * 1024,
        package_count: 10,
        oldest_entry: 1704067200,
        newest_entry: 1704153600,
    };
    assert_eq!(stats.total_size, 1024 * 1024);
    assert_eq!(stats.package_count, 10);
}

#[test]
fn test_cache_stats_clone() {
    let stats = CacheStats {
        total_size: 2048,
        package_count: 5,
        oldest_entry: 1000,
        newest_entry: 2000,
    };
    let cloned = stats.clone();
    assert_eq!(stats.total_size, cloned.total_size);
    assert_eq!(stats.package_count, cloned.package_count);
}

#[test]
fn test_cache_stats_debug_format() {
    let stats = CacheStats {
        total_size: 100,
        package_count: 1,
        oldest_entry: 0,
        newest_entry: 0,
    };
    let debug_str = alloc::format!("{:?}", stats);
    assert!(debug_str.contains("CacheStats"));
}

#[test]
fn test_get_cache_dir() {
    let dir = get_cache_dir();
    assert!(!dir.is_empty());
    assert!(dir.starts_with('/'));
    assert!(dir.contains("npkg"));
}

#[test]
fn test_cache_policy_debug_format() {
    let policy = CachePolicy::KeepAll;
    let debug_str = alloc::format!("{:?}", policy);
    assert!(debug_str.contains("KeepAll"));
}

#[test]
fn test_cache_stats_empty() {
    let stats = CacheStats {
        total_size: 0,
        package_count: 0,
        oldest_entry: 0,
        newest_entry: 0,
    };
    assert_eq!(stats.total_size, 0);
    assert_eq!(stats.package_count, 0);
}

#[test]
fn test_cache_stats_large_values() {
    let stats = CacheStats {
        total_size: u64::MAX,
        package_count: u32::MAX,
        oldest_entry: 0,
        newest_entry: u64::MAX,
    };
    assert_eq!(stats.total_size, u64::MAX);
    assert_eq!(stats.package_count, u32::MAX);
}

#[test]
fn test_cache_policy_consistency() {
    let policy1 = CachePolicy::KeepAll;
    let policy2 = CachePolicy::KeepAll;
    assert_eq!(policy1, policy2);
}

#[test]
fn test_cache_dir_format() {
    let dir = get_cache_dir();
    assert!(!dir.contains(".."));
    assert!(!dir.contains("//"));
}
