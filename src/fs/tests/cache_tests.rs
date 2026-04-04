use crate::fs::cache::*;

#[test]
fn test_cache_stats_default() {
    let stats = CacheStats::default();
    assert_eq!(stats.hits, 0);
    assert_eq!(stats.misses, 0);
    assert_eq!(stats.evictions, 0);
    assert_eq!(stats.writebacks, 0);
    assert_eq!(stats.pages_used, 0);
    assert_eq!(stats.dirty_pages, 0);
    assert_eq!(stats.bytes_cached, 0);
}

#[test]
fn test_cache_stats_hit_ratio_zero() {
    let stats = CacheStats::default();
    assert!((stats.hit_ratio() - 0.0).abs() < 0.001);
}

#[test]
fn test_cache_stats_hit_ratio_all_hits() {
    let stats = CacheStats {
        hits: 100,
        misses: 0,
        evictions: 0,
        writebacks: 0,
        pages_used: 0,
        dirty_pages: 0,
        bytes_cached: 0,
    };
    assert!((stats.hit_ratio() - 1.0).abs() < 0.001);
}

#[test]
fn test_cache_stats_hit_ratio_all_misses() {
    let stats = CacheStats {
        hits: 0,
        misses: 100,
        evictions: 0,
        writebacks: 0,
        pages_used: 0,
        dirty_pages: 0,
        bytes_cached: 0,
    };
    assert!((stats.hit_ratio() - 0.0).abs() < 0.001);
}

#[test]
fn test_cache_stats_hit_ratio_mixed() {
    let stats = CacheStats {
        hits: 75,
        misses: 25,
        evictions: 5,
        writebacks: 10,
        pages_used: 50,
        dirty_pages: 5,
        bytes_cached: 204800,
    };
    assert!((stats.hit_ratio() - 0.75).abs() < 0.001);
}

#[test]
fn test_cache_stats_clone() {
    let stats = CacheStats {
        hits: 100,
        misses: 50,
        evictions: 10,
        writebacks: 5,
        pages_used: 200,
        dirty_pages: 20,
        bytes_cached: 819200,
    };
    let cloned = stats.clone();
    assert_eq!(cloned.hits, 100);
    assert_eq!(cloned.misses, 50);
    assert_eq!(cloned.pages_used, 200);
}

#[test]
fn test_cache_statistics_new() {
    let stats = CacheStatistics::new();
    assert_eq!(stats.hits.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(stats.misses.load(core::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn test_cache_statistics_hit_ratio_zero() {
    let stats = CacheStatistics::new();
    assert!((stats.hit_ratio() - 0.0).abs() < 0.001);
}

#[test]
fn test_cache_statistics_reset() {
    CACHE_STATS.hits.store(100, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.misses.store(50, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.reset();
    assert_eq!(CACHE_STATS.hits.load(core::sync::atomic::Ordering::Relaxed), 0);
    assert_eq!(CACHE_STATS.misses.load(core::sync::atomic::Ordering::Relaxed), 0);
}

#[test]
fn test_cache_constants_max_cached_pages() {
    assert_eq!(MAX_CACHED_PAGES, 4096);
}

#[test]
fn test_cache_constants_writeback_batch_size() {
    assert_eq!(WRITEBACK_BATCH_SIZE, 32);
}

#[test]
fn test_cache_constants_max_cached_inodes() {
    assert_eq!(MAX_CACHED_INODES, 1024);
}

#[test]
fn test_cache_constants_max_operation_retries() {
    assert_eq!(MAX_OPERATION_RETRIES, 3);
}

#[test]
fn test_directory_entry_file() {
    let entry = DirectoryEntry {
        name: alloc::string::String::from("test.txt"),
        inode: 42,
        parent_inode: 1,
        file_type: 0,
        size: 1024,
    };
    assert_eq!(entry.name, "test.txt");
    assert_eq!(entry.inode, 42);
    assert_eq!(entry.parent_inode, 1);
    assert_eq!(entry.size, 1024);
}

#[test]
fn test_directory_entry_clone() {
    let entry = DirectoryEntry {
        name: alloc::string::String::from("subdir"),
        inode: 100,
        parent_inode: 1,
        file_type: 1,
        size: 0,
    };
    let cloned = entry.clone();
    assert_eq!(cloned.name, "subdir");
    assert_eq!(cloned.inode, 100);
}

#[test]
fn test_cached_inode_basic() {
    let inode = CachedInode {
        inode: 42,
        size: 1024,
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        atime: 1000,
        mtime: 2000,
        ctime: 3000,
        link_count: 1,
        ref_count: 1,
        dirty: false,
        accessed: 100,
    };
    assert_eq!(inode.inode, 42);
    assert_eq!(inode.size, 1024);
    assert_eq!(inode.mode, 0o644);
    assert!(!inode.dirty);
}

#[test]
fn test_cached_inode_dirty() {
    let inode = CachedInode {
        inode: 1,
        size: 0,
        mode: 0o755,
        uid: 0,
        gid: 0,
        atime: 0,
        mtime: 0,
        ctime: 0,
        link_count: 2,
        ref_count: 0,
        dirty: true,
        accessed: 0,
    };
    assert!(inode.dirty);
    assert_eq!(inode.link_count, 2);
}

#[test]
fn test_cached_inode_clone() {
    let inode = CachedInode {
        inode: 10,
        size: 512,
        mode: 0o600,
        uid: 500,
        gid: 500,
        atime: 100,
        mtime: 200,
        ctime: 300,
        link_count: 1,
        ref_count: 2,
        dirty: true,
        accessed: 50,
    };
    let cloned = inode.clone();
    assert_eq!(cloned.inode, 10);
    assert_eq!(cloned.ref_count, 2);
    assert!(cloned.dirty);
}

#[test]
fn test_dirty_page_basic() {
    let page = DirtyPage {
        offset: 4096,
        data: alloc::vec![1, 2, 3, 4],
    };
    assert_eq!(page.offset, 4096);
    assert_eq!(page.data.len(), 4);
}

#[test]
fn test_file_info_basic() {
    let info = FileInfo {
        path: alloc::string::String::from("/test/file.txt"),
        inode: 42,
        retries: 0,
        last_attempt: 1000,
    };
    assert_eq!(info.path, "/test/file.txt");
    assert_eq!(info.inode, 42);
    assert_eq!(info.retries, 0);
}

#[test]
fn test_file_info_clone() {
    let info = FileInfo {
        path: alloc::string::String::from("/data/log"),
        inode: 100,
        retries: 2,
        last_attempt: 5000,
    };
    let cloned = info.clone();
    assert_eq!(cloned.path, "/data/log");
    assert_eq!(cloned.retries, 2);
}

#[test]
fn test_get_cache_statistics() {
    CACHE_STATS.reset();
    CACHE_STATS.hits.store(100, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.misses.store(50, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.evictions.store(10, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.writebacks.store(5, core::sync::atomic::Ordering::Relaxed);

    let (hits, misses, evictions, writebacks) = get_cache_statistics();
    assert_eq!(hits, 100);
    assert_eq!(misses, 50);
    assert_eq!(evictions, 10);
    assert_eq!(writebacks, 5);
}

#[test]
fn test_get_cache_hit_ratio() {
    CACHE_STATS.reset();
    CACHE_STATS.hits.store(80, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.misses.store(20, core::sync::atomic::Ordering::Relaxed);

    let ratio = get_cache_hit_ratio();
    assert!((ratio - 0.8).abs() < 0.001);
}

#[test]
fn test_init_all_caches() {
    init_all_caches();
}

#[test]
fn test_clear_all_caches() {
    init_all_caches();
    clear_all_caches();
}

#[test]
fn test_init_page_cache() {
    init_page_cache();
}

#[test]
fn test_clear_page_cache() {
    init_page_cache();
    clear_page_cache();
}

#[test]
fn test_get_page_cache_stats() {
    init_page_cache();
    let (pages, dirty, bytes) = get_page_cache_stats();
    assert!(pages >= 0);
    assert!(dirty >= 0);
    assert!(bytes >= 0);
}

#[test]
fn test_init_dentry_cache() {
    init_dentry_cache();
}

#[test]
fn test_clear_dentry_cache() {
    init_dentry_cache();
    clear_dentry_cache();
}

#[test]
fn test_init_inode_cache() {
    init_inode_cache();
}

#[test]
fn test_clear_inode_cache() {
    init_inode_cache();
    clear_inode_cache();
}

#[test]
fn test_cleanup_unused_inodes() {
    init_inode_cache();
    let removed = cleanup_unused_inodes(10);
    assert!(removed >= 0);
}

#[test]
fn test_update_inode_timestamps() {
    init_inode_cache();
    let updated = update_inode_timestamps(10);
    assert!(updated >= 0);
}

#[test]
fn test_writeback_dirty_inodes() {
    init_inode_cache();
    let written = writeback_dirty_inodes(10);
    assert!(written >= 0);
}

#[test]
fn test_get_full_cache_statistics() {
    init_all_caches();
    let stats = get_full_cache_statistics();
    assert!(stats.pages_used >= 0);
    assert!(stats.dirty_pages >= 0);
}

#[test]
fn test_lookup_dentry_not_found() {
    init_dentry_cache();
    clear_dentry_cache();
    let result = lookup_dentry("/nonexistent/path");
    assert!(result.is_none());
}

#[test]
fn test_update_directory_entry() {
    init_dentry_cache();
    let entry = DirectoryEntry {
        name: alloc::string::String::from("/test/entry"),
        inode: 42,
        parent_inode: 1,
        file_type: 0,
        size: 100,
    };
    let result = update_directory_entry(&entry);
    assert!(result.is_ok());
}

#[test]
fn test_lookup_dentry_after_insert() {
    init_dentry_cache();
    let entry = DirectoryEntry {
        name: alloc::string::String::from("/test/lookup"),
        inode: 50,
        parent_inode: 1,
        file_type: 0,
        size: 200,
    };
    let _ = update_directory_entry(&entry);
    let found = lookup_dentry("/test/lookup");
    assert!(found.is_some());
    assert_eq!(found.unwrap().inode, 50);
}

#[test]
fn test_remove_dentry() {
    init_dentry_cache();
    let entry = DirectoryEntry {
        name: alloc::string::String::from("/test/remove"),
        inode: 60,
        parent_inode: 1,
        file_type: 0,
        size: 0,
    };
    let _ = update_directory_entry(&entry);
    remove_dentry("/test/remove");
    let found = lookup_dentry("/test/remove");
    assert!(found.is_none());
}

#[test]
fn test_queue_dentry_update() {
    init_dentry_cache();
    let entry = DirectoryEntry {
        name: alloc::string::String::from("/test/queue"),
        inode: 70,
        parent_inode: 1,
        file_type: 0,
        size: 0,
    };
    queue_dentry_update(entry);
}

#[test]
fn test_get_pending_dentry_updates() {
    init_dentry_cache();
    let updates = get_pending_dentry_updates();
    assert!(updates.len() <= 32);
}

#[test]
fn test_process_inode_cache_maintenance() {
    init_inode_cache();
    let processed = process_inode_cache_maintenance(100);
    assert!(processed >= 0);
}

#[test]
fn test_cache_page() {
    init_page_cache();
    let data = alloc::vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    cache_page(1, 0, data, false);
}

#[test]
fn test_get_cached_page() {
    init_page_cache();
    let data = alloc::vec![10u8, 20, 30, 40];
    cache_page(2, 4096, data.clone(), false);
    let cached = get_cached_page(2, 4096);
    assert!(cached.is_some());
    assert_eq!(cached.unwrap(), data);
}

#[test]
fn test_get_cached_page_not_found() {
    init_page_cache();
    let cached = get_cached_page(99999, 0);
    assert!(cached.is_none());
}

#[test]
fn test_mark_page_clean() {
    init_page_cache();
    let data = alloc::vec![1u8, 2, 3];
    cache_page(3, 0, data, true);
    mark_page_clean(3, 0);
}

#[test]
fn test_cache_inode() {
    init_inode_cache();
    let inode = CachedInode {
        inode: 42,
        size: 1024,
        mode: 0o644,
        uid: 1000,
        gid: 1000,
        atime: 0,
        mtime: 0,
        ctime: 0,
        link_count: 1,
        ref_count: 0,
        dirty: false,
        accessed: 0,
    };
    cache_inode(inode);
}

#[test]
fn test_get_cached_inode() {
    init_inode_cache();
    let inode = CachedInode {
        inode: 100,
        size: 2048,
        mode: 0o755,
        uid: 0,
        gid: 0,
        atime: 1000,
        mtime: 2000,
        ctime: 3000,
        link_count: 2,
        ref_count: 1,
        dirty: true,
        accessed: 50,
    };
    cache_inode(inode);
    let cached = get_cached_inode(100);
    assert!(cached.is_some());
    assert_eq!(cached.unwrap().size, 2048);
}

#[test]
fn test_get_cached_inode_not_found() {
    init_inode_cache();
    let cached = get_cached_inode(99999);
    assert!(cached.is_none());
}
