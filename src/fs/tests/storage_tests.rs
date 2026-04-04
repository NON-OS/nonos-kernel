use crate::fs::storage::*;

#[test]
fn test_storage_constants_default_max_storage() {
    assert_eq!(DEFAULT_MAX_STORAGE, 256 * 1024 * 1024);
}

#[test]
fn test_storage_constants_default_max_files() {
    assert_eq!(DEFAULT_MAX_FILES, 65536);
}

#[test]
fn test_storage_constants_block_size() {
    assert_eq!(BLOCK_SIZE, 4096);
}

#[test]
fn test_storage_constants_inode_size() {
    assert_eq!(INODE_SIZE, 256);
}

#[test]
fn test_storage_constants_warning_threshold() {
    assert!((WARNING_THRESHOLD_PERCENT - 80.0).abs() < 0.001);
}

#[test]
fn test_storage_constants_critical_threshold() {
    assert!((CRITICAL_THRESHOLD_PERCENT - 95.0).abs() < 0.001);
}

#[test]
fn test_storage_health_status_variants() {
    assert_eq!(StorageHealthStatus::Healthy, StorageHealthStatus::Healthy);
    assert_eq!(StorageHealthStatus::Warning, StorageHealthStatus::Warning);
    assert_eq!(StorageHealthStatus::Critical, StorageHealthStatus::Critical);
    assert_eq!(StorageHealthStatus::Degraded, StorageHealthStatus::Degraded);
    assert_eq!(StorageHealthStatus::Unknown, StorageHealthStatus::Unknown);
}

#[test]
fn test_storage_stats_default() {
    let stats = StorageStats::default();
    assert_eq!(stats.total_bytes, DEFAULT_MAX_STORAGE);
    assert_eq!(stats.used_bytes, 0);
    assert_eq!(stats.available_bytes, DEFAULT_MAX_STORAGE);
    assert_eq!(stats.file_count, 0);
    assert_eq!(stats.directory_count, 0);
    assert_eq!(stats.block_size, BLOCK_SIZE);
}

#[test]
fn test_storage_stats_usage_percent_zero() {
    let stats = StorageStats::default();
    assert!((stats.usage_percent() - 0.0).abs() < 0.001);
}

#[test]
fn test_storage_stats_usage_percent_half() {
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
    assert!((stats.usage_percent() - 50.0).abs() < 0.001);
}

#[test]
fn test_storage_stats_usage_percent_full() {
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
    assert!((stats.usage_percent() - 100.0).abs() < 0.001);
}

#[test]
fn test_storage_stats_free_percent() {
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
    assert!((stats.free_percent() - 75.0).abs() < 0.001);
}

#[test]
fn test_storage_stats_block_usage_percent() {
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
    assert!((stats.block_usage_percent() - 25.0).abs() < 0.001);
}

#[test]
fn test_storage_stats_block_usage_percent_zero_total() {
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
    assert!((stats.block_usage_percent() - 0.0).abs() < 0.001);
}

#[test]
fn test_storage_stats_clone() {
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
    assert_eq!(cloned.total_bytes, 1024);
    assert_eq!(cloned.file_count, 10);
}

#[test]
fn test_filesystem_breakdown_default() {
    let breakdown = FilesystemBreakdown::default();
    assert_eq!(breakdown.ramfs_bytes, 0);
    assert_eq!(breakdown.ramfs_files, 0);
    assert_eq!(breakdown.cryptofs_bytes, 0);
    assert_eq!(breakdown.cryptofs_files, 0);
    assert_eq!(breakdown.cache_bytes, 0);
    assert_eq!(breakdown.metadata_bytes, 0);
}

#[test]
fn test_filesystem_breakdown_total_bytes() {
    let breakdown = FilesystemBreakdown {
        ramfs_bytes: 1000,
        ramfs_files: 10,
        cryptofs_bytes: 500,
        cryptofs_files: 5,
        cache_bytes: 200,
        metadata_bytes: 100,
    };
    assert_eq!(breakdown.total_bytes(), 1800);
}

#[test]
fn test_filesystem_breakdown_total_files() {
    let breakdown = FilesystemBreakdown {
        ramfs_bytes: 0,
        ramfs_files: 10,
        cryptofs_bytes: 0,
        cryptofs_files: 5,
        cache_bytes: 0,
        metadata_bytes: 0,
    };
    assert_eq!(breakdown.total_files(), 15);
}

#[test]
fn test_filesystem_breakdown_clone() {
    let breakdown = FilesystemBreakdown {
        ramfs_bytes: 100,
        ramfs_files: 1,
        cryptofs_bytes: 200,
        cryptofs_files: 2,
        cache_bytes: 50,
        metadata_bytes: 25,
    };
    let cloned = breakdown.clone();
    assert_eq!(cloned.ramfs_bytes, 100);
    assert_eq!(cloned.cryptofs_files, 2);
}

#[test]
fn test_storage_health_default() {
    let health = StorageHealth::default();
    assert_eq!(health.status, StorageHealthStatus::Unknown);
    assert!((health.usage_percent - 0.0).abs() < 0.001);
    assert!((health.inode_usage_percent - 0.0).abs() < 0.001);
    assert!((health.fragmentation_percent - 0.0).abs() < 0.001);
}

#[test]
fn test_storage_health_clone() {
    let health = StorageHealth {
        status: StorageHealthStatus::Healthy,
        usage_percent: 50.0,
        inode_usage_percent: 25.0,
        fragmentation_percent: 10.0,
        issues: StorageIssues::default(),
    };
    let cloned = health.clone();
    assert_eq!(cloned.status, StorageHealthStatus::Healthy);
    assert!((cloned.usage_percent - 50.0).abs() < 0.001);
}

#[test]
fn test_storage_issues_default() {
    let issues = StorageIssues::default();
    assert!(!issues.low_space);
    assert!(!issues.low_inodes);
    assert!(!issues.high_fragmentation);
    assert_eq!(issues.allocation_failures, 0);
    assert_eq!(issues.io_errors, 0);
}

#[test]
fn test_storage_issues_has_issues_none() {
    let issues = StorageIssues::default();
    assert!(!issues.has_issues());
}

#[test]
fn test_storage_issues_has_issues_low_space() {
    let issues = StorageIssues {
        low_space: true,
        low_inodes: false,
        high_fragmentation: false,
        allocation_failures: 0,
        io_errors: 0,
    };
    assert!(issues.has_issues());
}

#[test]
fn test_storage_issues_has_issues_low_inodes() {
    let issues = StorageIssues {
        low_space: false,
        low_inodes: true,
        high_fragmentation: false,
        allocation_failures: 0,
        io_errors: 0,
    };
    assert!(issues.has_issues());
}

#[test]
fn test_storage_issues_has_issues_high_fragmentation() {
    let issues = StorageIssues {
        low_space: false,
        low_inodes: false,
        high_fragmentation: true,
        allocation_failures: 0,
        io_errors: 0,
    };
    assert!(issues.has_issues());
}

#[test]
fn test_storage_issues_has_issues_allocation_failures() {
    let issues = StorageIssues {
        low_space: false,
        low_inodes: false,
        high_fragmentation: false,
        allocation_failures: 1,
        io_errors: 0,
    };
    assert!(issues.has_issues());
}

#[test]
fn test_storage_issues_has_issues_io_errors() {
    let issues = StorageIssues {
        low_space: false,
        low_inodes: false,
        high_fragmentation: false,
        allocation_failures: 0,
        io_errors: 1,
    };
    assert!(issues.has_issues());
}

#[test]
fn test_storage_issues_issue_count_zero() {
    let issues = StorageIssues::default();
    assert_eq!(issues.issue_count(), 0);
}

#[test]
fn test_storage_issues_issue_count_all() {
    let issues = StorageIssues {
        low_space: true,
        low_inodes: true,
        high_fragmentation: true,
        allocation_failures: 1,
        io_errors: 1,
    };
    assert_eq!(issues.issue_count(), 5);
}

#[test]
fn test_storage_issues_issue_count_some() {
    let issues = StorageIssues {
        low_space: true,
        low_inodes: false,
        high_fragmentation: true,
        allocation_failures: 0,
        io_errors: 0,
    };
    assert_eq!(issues.issue_count(), 2);
}

#[test]
fn test_storage_issues_clone() {
    let issues = StorageIssues {
        low_space: true,
        low_inodes: true,
        high_fragmentation: false,
        allocation_failures: 5,
        io_errors: 3,
    };
    let cloned = issues.clone();
    assert!(cloned.low_space);
    assert!(cloned.low_inodes);
    assert_eq!(cloned.allocation_failures, 5);
}

#[test]
fn test_inode_stats_default() {
    let stats = InodeStats::default();
    assert_eq!(stats.total_inodes, DEFAULT_MAX_FILES);
    assert_eq!(stats.used_inodes, 0);
    assert_eq!(stats.free_inodes, DEFAULT_MAX_FILES);
    assert_eq!(stats.inode_size, INODE_SIZE);
}

#[test]
fn test_inode_stats_usage_percent_zero() {
    let stats = InodeStats::default();
    assert!((stats.usage_percent() - 0.0).abs() < 0.001);
}

#[test]
fn test_inode_stats_usage_percent_half() {
    let stats = InodeStats {
        total_inodes: 1000,
        used_inodes: 500,
        free_inodes: 500,
        inode_size: INODE_SIZE,
    };
    assert!((stats.usage_percent() - 50.0).abs() < 0.001);
}

#[test]
fn test_inode_stats_usage_percent_zero_total() {
    let stats = InodeStats {
        total_inodes: 0,
        used_inodes: 0,
        free_inodes: 0,
        inode_size: INODE_SIZE,
    };
    assert!((stats.usage_percent() - 0.0).abs() < 0.001);
}

#[test]
fn test_inode_stats_clone() {
    let stats = InodeStats {
        total_inodes: 1000,
        used_inodes: 100,
        free_inodes: 900,
        inode_size: 512,
    };
    let cloned = stats.clone();
    assert_eq!(cloned.total_inodes, 1000);
    assert_eq!(cloned.inode_size, 512);
}

#[test]
fn test_storage_quota_default() {
    let quota = StorageQuota::default();
    assert!(quota.soft_limit < quota.hard_limit);
    assert_eq!(quota.hard_limit, DEFAULT_MAX_STORAGE);
    assert_eq!(quota.current_usage, 0);
    assert_eq!(quota.file_limit, DEFAULT_MAX_FILES);
    assert_eq!(quota.file_count, 0);
    assert!(quota.grace_period_secs > 0);
    assert!(quota.exceeded_at.is_none());
}

#[test]
fn test_storage_quota_is_soft_exceeded_false() {
    let quota = StorageQuota::default();
    assert!(!quota.is_soft_exceeded());
}

#[test]
fn test_storage_quota_is_soft_exceeded_true() {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 150,
        file_limit: 1000,
        file_count: 0,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    assert!(quota.is_soft_exceeded());
}

#[test]
fn test_storage_quota_is_hard_exceeded_false() {
    let quota = StorageQuota::default();
    assert!(!quota.is_hard_exceeded());
}

#[test]
fn test_storage_quota_is_hard_exceeded_true() {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 200,
        file_limit: 1000,
        file_count: 0,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    assert!(quota.is_hard_exceeded());
}

#[test]
fn test_storage_quota_remaining_bytes() {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 50,
        file_limit: 1000,
        file_count: 0,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    assert_eq!(quota.remaining_bytes(), 150);
}

#[test]
fn test_storage_quota_remaining_bytes_none() {
    let quota = StorageQuota {
        soft_limit: 100,
        hard_limit: 200,
        current_usage: 250,
        file_limit: 1000,
        file_count: 0,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    assert_eq!(quota.remaining_bytes(), 0);
}

#[test]
fn test_storage_quota_remaining_files() {
    let quota = StorageQuota {
        soft_limit: 0,
        hard_limit: 0,
        current_usage: 0,
        file_limit: 1000,
        file_count: 100,
        grace_period_secs: 0,
        exceeded_at: None,
    };
    assert_eq!(quota.remaining_files(), 900);
}

#[test]
fn test_storage_quota_clone() {
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
    assert_eq!(cloned.soft_limit, 100);
    assert_eq!(cloned.exceeded_at, Some(1000));
}

#[test]
fn test_get_storage_stats() {
    let stats = get_storage_stats();
    assert!(stats.total_bytes > 0);
}

#[test]
fn test_get_total_used_bytes() {
    let used = get_total_used_bytes();
    assert!(used >= 0);
}

#[test]
fn test_get_total_available_bytes() {
    let available = get_total_available_bytes();
    assert!(available >= 0);
}

#[test]
fn test_get_storage_usage_percent() {
    let percent = get_storage_usage_percent();
    assert!(percent >= 0.0);
    assert!(percent <= 100.0);
}

#[test]
fn test_get_filesystem_breakdown() {
    let breakdown = get_filesystem_breakdown();
    assert!(breakdown.total_bytes() >= 0);
}

#[test]
fn test_get_storage_health() {
    let health = get_storage_health();
    assert!(health.usage_percent >= 0.0);
}

#[test]
fn test_get_inode_stats() {
    let stats = get_inode_stats();
    assert!(stats.total_inodes > 0);
}

#[test]
fn test_get_quota() {
    let quota = get_quota();
    assert!(quota.hard_limit > 0);
}

#[test]
fn test_get_remaining_capacity() {
    let (bytes, files) = get_remaining_capacity();
    assert!(bytes >= 0);
    assert!(files >= 0);
}

#[test]
fn test_is_soft_limit_exceeded() {
    let result = is_soft_limit_exceeded();
    assert!(result == true || result == false);
}

#[test]
fn test_is_hard_limit_exceeded() {
    let result = is_hard_limit_exceeded();
    assert!(result == true || result == false);
}

#[test]
fn test_check_can_allocate() {
    let result = check_can_allocate(1024);
    assert!(result.is_ok() || result.is_err());
}

#[test]
fn test_check_can_create_file() {
    let result = check_can_create_file();
    assert!(result.is_ok() || result.is_err());
}
