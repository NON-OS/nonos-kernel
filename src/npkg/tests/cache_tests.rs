use crate::npkg::cache::{CachePolicy, CacheStats};
use crate::npkg::*;
use crate::test::framework::TestResult;

pub(crate) fn test_cache_policy_default() -> TestResult {
    let policy: CachePolicy = Default::default();
    if policy != CachePolicy::KeepLatest {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_policy_variants() -> TestResult {
    let policies = [
        CachePolicy::KeepAll,
        CachePolicy::KeepLatest,
        CachePolicy::KeepInstalled,
        CachePolicy::KeepNone,
    ];
    if policies.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_policy_equality() -> TestResult {
    if CachePolicy::KeepAll != CachePolicy::KeepAll {
        return TestResult::Fail;
    }
    if CachePolicy::KeepLatest != CachePolicy::KeepLatest {
        return TestResult::Fail;
    }
    if CachePolicy::KeepInstalled != CachePolicy::KeepInstalled {
        return TestResult::Fail;
    }
    if CachePolicy::KeepNone != CachePolicy::KeepNone {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_policy_inequality() -> TestResult {
    if CachePolicy::KeepAll == CachePolicy::KeepNone {
        return TestResult::Fail;
    }
    if CachePolicy::KeepLatest == CachePolicy::KeepInstalled {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_policy_copy() -> TestResult {
    let policy = CachePolicy::KeepAll;
    let copied = policy;
    if policy != copied {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_policy_clone() -> TestResult {
    let policy = CachePolicy::KeepLatest;
    let cloned = policy.clone();
    if policy != cloned {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_structure() -> TestResult {
    let stats = CacheStats {
        total_size: 1024 * 1024,
        package_count: 10,
        oldest_entry: 1704067200,
        newest_entry: 1704153600,
    };
    if stats.total_size != 1024 * 1024 {
        return TestResult::Fail;
    }
    if stats.package_count != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_clone() -> TestResult {
    let stats =
        CacheStats { total_size: 2048, package_count: 5, oldest_entry: 1000, newest_entry: 2000 };
    let cloned = stats.clone();
    if stats.total_size != cloned.total_size {
        return TestResult::Fail;
    }
    if stats.package_count != cloned.package_count {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_debug_format() -> TestResult {
    let stats = CacheStats { total_size: 100, package_count: 1, oldest_entry: 0, newest_entry: 0 };
    let debug_str = alloc::format!("{:?}", stats);
    if !debug_str.contains("CacheStats") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_cache_dir() -> TestResult {
    let dir = get_cache_dir();
    if dir.is_empty() {
        return TestResult::Fail;
    }
    if !dir.starts_with('/') {
        return TestResult::Fail;
    }
    if !dir.contains("npkg") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_policy_debug_format() -> TestResult {
    let policy = CachePolicy::KeepAll;
    let debug_str = alloc::format!("{:?}", policy);
    if !debug_str.contains("KeepAll") {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_empty() -> TestResult {
    let stats = CacheStats { total_size: 0, package_count: 0, oldest_entry: 0, newest_entry: 0 };
    if stats.total_size != 0 {
        return TestResult::Fail;
    }
    if stats.package_count != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_large_values() -> TestResult {
    let stats = CacheStats {
        total_size: u64::MAX,
        package_count: u32::MAX,
        oldest_entry: 0,
        newest_entry: u64::MAX,
    };
    if stats.total_size != u64::MAX {
        return TestResult::Fail;
    }
    if stats.package_count != u32::MAX {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_policy_consistency() -> TestResult {
    let policy1 = CachePolicy::KeepAll;
    let policy2 = CachePolicy::KeepAll;
    if policy1 != policy2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_dir_format() -> TestResult {
    let dir = get_cache_dir();
    if dir.contains("..") {
        return TestResult::Fail;
    }
    if dir.contains("//") {
        return TestResult::Fail;
    }
    TestResult::Pass
}
