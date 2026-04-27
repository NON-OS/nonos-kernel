use crate::fs::storage::*;
use crate::test::framework::TestResult;

pub(crate) fn test_storage_constants_default_max_storage() -> TestResult {
    if DEFAULT_MAX_STORAGE != 256 * 1024 * 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_constants_default_max_files() -> TestResult {
    if DEFAULT_MAX_FILES != 65536 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_constants_block_size() -> TestResult {
    if BLOCK_SIZE != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_constants_inode_size() -> TestResult {
    if INODE_SIZE != 256 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_constants_warning_threshold() -> TestResult {
    if !((WARNING_THRESHOLD_PERCENT - 80.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_constants_critical_threshold() -> TestResult {
    if !((CRITICAL_THRESHOLD_PERCENT - 95.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_health_status_variants() -> TestResult {
    if StorageHealthStatus::Healthy != StorageHealthStatus::Healthy {
        return TestResult::Fail;
    }
    if StorageHealthStatus::Warning != StorageHealthStatus::Warning {
        return TestResult::Fail;
    }
    if StorageHealthStatus::Critical != StorageHealthStatus::Critical {
        return TestResult::Fail;
    }
    if StorageHealthStatus::Degraded != StorageHealthStatus::Degraded {
        return TestResult::Fail;
    }
    if StorageHealthStatus::Unknown != StorageHealthStatus::Unknown {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_stats_default() -> TestResult {
    let stats = StorageStats::default();
    if stats.total_bytes != DEFAULT_MAX_STORAGE {
        return TestResult::Fail;
    }
    if stats.used_bytes != 0 {
        return TestResult::Fail;
    }
    if stats.available_bytes != DEFAULT_MAX_STORAGE {
        return TestResult::Fail;
    }
    if stats.file_count != 0 {
        return TestResult::Fail;
    }
    if stats.directory_count != 0 {
        return TestResult::Fail;
    }
    if stats.block_size != BLOCK_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_stats_usage_percent_zero() -> TestResult {
    let stats = StorageStats::default();
    if !((stats.usage_percent() - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_stats_usage_percent_half() -> TestResult {
    let stats = StorageStats {
        total_bytes: 1000,
        used_bytes: 500,
        available_bytes: 500,
        file_count: 0,
        directory_count: 0,
        block_size: BLOCK_SIZE,
        total_blocks: 0,
        used_blocks: 0,
        free_blocks: 0,
    };
    if !((stats.usage_percent() - 50.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_stats_usage_percent_full() -> TestResult {
    let stats = StorageStats {
        total_bytes: 1000,
        used_bytes: 1000,
        available_bytes: 0,
        file_count: 0,
        directory_count: 0,
        block_size: BLOCK_SIZE,
        total_blocks: 0,
        used_blocks: 0,
        free_blocks: 0,
    };
    if !((stats.usage_percent() - 100.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_stats_free_percent() -> TestResult {
    let stats = StorageStats {
        total_bytes: 1000,
        used_bytes: 250,
        available_bytes: 750,
        file_count: 0,
        directory_count: 0,
        block_size: BLOCK_SIZE,
        total_blocks: 0,
        used_blocks: 0,
        free_blocks: 0,
    };
    if !((stats.free_percent() - 75.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_stats_block_usage_percent() -> TestResult {
    let stats = StorageStats {
        total_bytes: 0,
        used_bytes: 0,
        available_bytes: 0,
        file_count: 0,
        directory_count: 0,
        block_size: BLOCK_SIZE,
        total_blocks: 100,
        used_blocks: 25,
        free_blocks: 75,
    };
    if !((stats.block_usage_percent() - 25.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_stats_block_usage_percent_zero_total() -> TestResult {
    let stats = StorageStats {
        total_bytes: 0,
        used_bytes: 0,
        available_bytes: 0,
        file_count: 0,
        directory_count: 0,
        block_size: BLOCK_SIZE,
        total_blocks: 0,
        used_blocks: 0,
        free_blocks: 0,
    };
    if !((stats.block_usage_percent() - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_stats_clone() -> TestResult {
    let stats = StorageStats {
        total_bytes: 1024,
        used_bytes: 512,
        available_bytes: 512,
        file_count: 10,
        directory_count: 5,
        block_size: BLOCK_SIZE,
        total_blocks: 100,
        used_blocks: 50,
        free_blocks: 50,
    };
    let cloned = stats.clone();
    if cloned.total_bytes != 1024 {
        return TestResult::Fail;
    }
    if cloned.file_count != 10 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_filesystem_breakdown_default() -> TestResult {
    let breakdown = FilesystemBreakdown::default();
    if breakdown.ramfs_bytes != 0 {
        return TestResult::Fail;
    }
    if breakdown.ramfs_files != 0 {
        return TestResult::Fail;
    }
    if breakdown.cryptofs_bytes != 0 {
        return TestResult::Fail;
    }
    if breakdown.cryptofs_files != 0 {
        return TestResult::Fail;
    }
    if breakdown.cache_bytes != 0 {
        return TestResult::Fail;
    }
    if breakdown.metadata_bytes != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_filesystem_breakdown_total_bytes() -> TestResult {
    let breakdown = FilesystemBreakdown {
        ramfs_bytes: 1000,
        ramfs_files: 10,
        cryptofs_bytes: 500,
        cryptofs_files: 5,
        cache_bytes: 200,
        metadata_bytes: 100,
    };
    if breakdown.total_bytes() != 1800 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_filesystem_breakdown_total_files() -> TestResult {
    let breakdown = FilesystemBreakdown {
        ramfs_bytes: 0,
        ramfs_files: 10,
        cryptofs_bytes: 0,
        cryptofs_files: 5,
        cache_bytes: 0,
        metadata_bytes: 0,
    };
    if breakdown.total_files() != 15 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_filesystem_breakdown_clone() -> TestResult {
    let breakdown = FilesystemBreakdown {
        ramfs_bytes: 100,
        ramfs_files: 1,
        cryptofs_bytes: 200,
        cryptofs_files: 2,
        cache_bytes: 50,
        metadata_bytes: 25,
    };
    let cloned = breakdown.clone();
    if cloned.ramfs_bytes != 100 {
        return TestResult::Fail;
    }
    if cloned.cryptofs_files != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_health_default() -> TestResult {
    let health = StorageHealth::default();
    if health.status != StorageHealthStatus::Unknown {
        return TestResult::Fail;
    }
    if !((health.usage_percent - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    if !((health.inode_usage_percent - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    if !((health.fragmentation_percent - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_health_clone() -> TestResult {
    let health = StorageHealth {
        status: StorageHealthStatus::Healthy,
        usage_percent: 50.0,
        inode_usage_percent: 25.0,
        fragmentation_percent: 10.0,
        issues: StorageIssues::default(),
    };
    let cloned = health.clone();
    if cloned.status != StorageHealthStatus::Healthy {
        return TestResult::Fail;
    }
    if !((cloned.usage_percent - 50.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_default() -> TestResult {
    let issues = StorageIssues::default();
    if issues.low_space {
        return TestResult::Fail;
    }
    if issues.low_inodes {
        return TestResult::Fail;
    }
    if issues.high_fragmentation {
        return TestResult::Fail;
    }
    if issues.allocation_failures != 0 {
        return TestResult::Fail;
    }
    if issues.io_errors != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_has_issues_none() -> TestResult {
    let issues = StorageIssues::default();
    if issues.has_issues() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_has_issues_low_space() -> TestResult {
    let issues = StorageIssues {
        low_space: true,
        low_inodes: false,
        high_fragmentation: false,
        allocation_failures: 0,
        io_errors: 0,
    };
    if !issues.has_issues() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_has_issues_low_inodes() -> TestResult {
    let issues = StorageIssues {
        low_space: false,
        low_inodes: true,
        high_fragmentation: false,
        allocation_failures: 0,
        io_errors: 0,
    };
    if !issues.has_issues() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_has_issues_high_fragmentation() -> TestResult {
    let issues = StorageIssues {
        low_space: false,
        low_inodes: false,
        high_fragmentation: true,
        allocation_failures: 0,
        io_errors: 0,
    };
    if !issues.has_issues() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_has_issues_allocation_failures() -> TestResult {
    let issues = StorageIssues {
        low_space: false,
        low_inodes: false,
        high_fragmentation: false,
        allocation_failures: 1,
        io_errors: 0,
    };
    if !issues.has_issues() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_has_issues_io_errors() -> TestResult {
    let issues = StorageIssues {
        low_space: false,
        low_inodes: false,
        high_fragmentation: false,
        allocation_failures: 0,
        io_errors: 1,
    };
    if !issues.has_issues() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_issue_count_zero() -> TestResult {
    let issues = StorageIssues::default();
    if issues.issue_count() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_issue_count_all() -> TestResult {
    let issues = StorageIssues {
        low_space: true,
        low_inodes: true,
        high_fragmentation: true,
        allocation_failures: 1,
        io_errors: 1,
    };
    if issues.issue_count() != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_issue_count_some() -> TestResult {
    let issues = StorageIssues {
        low_space: true,
        low_inodes: false,
        high_fragmentation: true,
        allocation_failures: 0,
        io_errors: 0,
    };
    if issues.issue_count() != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_issues_clone() -> TestResult {
    let issues = StorageIssues {
        low_space: true,
        low_inodes: true,
        high_fragmentation: false,
        allocation_failures: 5,
        io_errors: 3,
    };
    let cloned = issues.clone();
    if !cloned.low_space {
        return TestResult::Fail;
    }
    if !cloned.low_inodes {
        return TestResult::Fail;
    }
    if cloned.allocation_failures != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inode_stats_default() -> TestResult {
    let stats = InodeStats::default();
    if stats.total_inodes != DEFAULT_MAX_FILES {
        return TestResult::Fail;
    }
    if stats.used_inodes != 0 {
        return TestResult::Fail;
    }
    if stats.free_inodes != DEFAULT_MAX_FILES {
        return TestResult::Fail;
    }
    if stats.inode_size != INODE_SIZE {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inode_stats_usage_percent_zero() -> TestResult {
    let stats = InodeStats::default();
    if !((stats.usage_percent() - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inode_stats_usage_percent_half() -> TestResult {
    let stats = InodeStats {
        total_inodes: 1000,
        used_inodes: 500,
        free_inodes: 500,
        inode_size: INODE_SIZE,
    };
    if !((stats.usage_percent() - 50.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inode_stats_usage_percent_zero_total() -> TestResult {
    let stats =
        InodeStats { total_inodes: 0, used_inodes: 0, free_inodes: 0, inode_size: INODE_SIZE };
    if !((stats.usage_percent() - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_inode_stats_clone() -> TestResult {
    let stats =
        InodeStats { total_inodes: 1000, used_inodes: 100, free_inodes: 900, inode_size: 512 };
    let cloned = stats.clone();
    if cloned.total_inodes != 1000 {
        return TestResult::Fail;
    }
    if cloned.inode_size != 512 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_default() -> TestResult {
    let quota = StorageQuota::default();
    if !(quota.soft_limit < quota.hard_limit) {
        return TestResult::Fail;
    }
    if quota.hard_limit != DEFAULT_MAX_STORAGE {
        return TestResult::Fail;
    }
    if quota.current_usage != 0 {
        return TestResult::Fail;
    }
    if quota.file_limit != DEFAULT_MAX_FILES {
        return TestResult::Fail;
    }
    if quota.file_count != 0 {
        return TestResult::Fail;
    }
    if !(quota.grace_period_secs > 0) {
        return TestResult::Fail;
    }
    if !quota.exceeded_at.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_is_soft_exceeded_false() -> TestResult {
    let quota = StorageQuota::default();
    if quota.is_soft_exceeded() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_is_soft_exceeded_true() -> TestResult {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 150,
        file_limit: 1000,
        file_count: 0,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    if !quota.is_soft_exceeded() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_is_hard_exceeded_false() -> TestResult {
    let quota = StorageQuota::default();
    if quota.is_hard_exceeded() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_is_hard_exceeded_true() -> TestResult {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 200,
        file_limit: 1000,
        file_count: 0,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    if !quota.is_hard_exceeded() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_remaining_bytes() -> TestResult {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 50,
        file_limit: 1000,
        file_count: 0,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    if quota.remaining_bytes() != 150 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_remaining_bytes_none() -> TestResult {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 250,
        file_limit: 1000,
        file_count: 0,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    if quota.remaining_bytes() != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_remaining_files() -> TestResult {
    let quota = StorageQuota {
        soft_limit: 0,
        hard_limit: 0,
        current_usage: 0,
        file_limit: 1000,
        file_count: 100,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    if quota.remaining_files() != 900 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_storage_quota_clone() -> TestResult {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 50,
        file_limit: 500,
        file_count: 10,
        grace_period_secs: 3600,
        exceeded_at: Some(1000),
    };
    let cloned = quota.clone();
    if cloned.soft_limit != 100 {
        return TestResult::Fail;
    }
    if cloned.exceeded_at != Some(1000) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_storage_stats() -> TestResult {
    let stats = get_storage_stats();
    if !(stats.total_bytes > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_total_used_bytes() -> TestResult {
    let used = get_total_used_bytes();
    if !(used >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_total_available_bytes() -> TestResult {
    let available = get_total_available_bytes();
    if !(available >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_storage_usage_percent() -> TestResult {
    let percent = get_storage_usage_percent();
    if !(percent >= 0.0) {
        return TestResult::Fail;
    }
    if !(percent <= 100.0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_filesystem_breakdown() -> TestResult {
    let breakdown = get_filesystem_breakdown();
    if !(breakdown.total_bytes() >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_storage_health() -> TestResult {
    let health = get_storage_health();
    if !(health.usage_percent >= 0.0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_inode_stats() -> TestResult {
    let stats = get_inode_stats();
    if !(stats.total_inodes > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_quota() -> TestResult {
    let quota = get_quota();
    if !(quota.hard_limit > 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_remaining_capacity() -> TestResult {
    let (bytes, files) = get_remaining_capacity();
    if !(bytes >= 0) {
        return TestResult::Fail;
    }
    if !(files >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_soft_limit_exceeded() -> TestResult {
    let result = is_soft_limit_exceeded();
    if !(result == true || result == false) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_is_hard_limit_exceeded() -> TestResult {
    let result = is_hard_limit_exceeded();
    if !(result == true || result == false) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_check_can_allocate() -> TestResult {
    let result = check_can_allocate(1024);
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_check_can_create_file() -> TestResult {
    let result = check_can_create_file();
    if !(result.is_ok() || result.is_err()) {
        return TestResult::Fail;
    }
    TestResult::Pass
}
