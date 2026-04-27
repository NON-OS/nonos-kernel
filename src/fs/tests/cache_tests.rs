use crate::fs::cache::*;
use crate::test::framework::TestResult;

pub(crate) fn test_cache_stats_default() -> TestResult {
    let stats = CacheStats::default();
    if stats.hits != 0 {
        return TestResult::Fail;
    }
    if stats.misses != 0 {
        return TestResult::Fail;
    }
    if stats.evictions != 0 {
        return TestResult::Fail;
    }
    if stats.writebacks != 0 {
        return TestResult::Fail;
    }
    if stats.pages_used != 0 {
        return TestResult::Fail;
    }
    if stats.dirty_pages != 0 {
        return TestResult::Fail;
    }
    if stats.bytes_cached != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_hit_ratio_zero() -> TestResult {
    let stats = CacheStats::default();
    if !((stats.hit_ratio() - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_hit_ratio_all_hits() -> TestResult {
    let stats = CacheStats {
        hits: 100,
        misses: 0,
        evictions: 0,
        writebacks: 0,
        pages_used: 0,
        dirty_pages: 0,
        bytes_cached: 0,
    };
    if !((stats.hit_ratio() - 1.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_hit_ratio_all_misses() -> TestResult {
    let stats = CacheStats {
        hits: 0,
        misses: 100,
        evictions: 0,
        writebacks: 0,
        pages_used: 0,
        dirty_pages: 0,
        bytes_cached: 0,
    };
    if !((stats.hit_ratio() - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_hit_ratio_mixed() -> TestResult {
    let stats = CacheStats {
        hits: 75,
        misses: 25,
        evictions: 5,
        writebacks: 10,
        pages_used: 50,
        dirty_pages: 5,
        bytes_cached: 204800,
    };
    if !((stats.hit_ratio() - 0.75).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_stats_clone() -> TestResult {
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
    if cloned.hits != 100 {
        return TestResult::Fail;
    }
    if cloned.misses != 50 {
        return TestResult::Fail;
    }
    if cloned.pages_used != 200 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_statistics_new() -> TestResult {
    let stats = CacheStatistics::new();
    if stats.hits.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if stats.misses.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_statistics_hit_ratio_zero() -> TestResult {
    let stats = CacheStatistics::new();
    if !((stats.hit_ratio() - 0.0).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_statistics_reset() -> TestResult {
    CACHE_STATS.hits.store(100, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.misses.store(50, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.reset();
    if CACHE_STATS.hits.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    if CACHE_STATS.misses.load(core::sync::atomic::Ordering::Relaxed) != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_constants_max_cached_pages() -> TestResult {
    if MAX_CACHED_PAGES != 4096 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_constants_writeback_batch_size() -> TestResult {
    if WRITEBACK_BATCH_SIZE != 32 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_constants_max_cached_inodes() -> TestResult {
    if MAX_CACHED_INODES != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_constants_max_operation_retries() -> TestResult {
    if MAX_OPERATION_RETRIES != 3 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_directory_entry_file() -> TestResult {
    let entry = DirectoryEntry {
        name: alloc::string::String::from("test.txt"),
        inode: 42,
        parent_inode: 1,
        file_type: 0,
        size: 1024,
    };
    if entry.name != "test.txt" {
        return TestResult::Fail;
    }
    if entry.inode != 42 {
        return TestResult::Fail;
    }
    if entry.parent_inode != 1 {
        return TestResult::Fail;
    }
    if entry.size != 1024 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_directory_entry_clone() -> TestResult {
    let entry = DirectoryEntry {
        name: alloc::string::String::from("subdir"),
        inode: 100,
        parent_inode: 1,
        file_type: 1,
        size: 0,
    };
    let cloned = entry.clone();
    if cloned.name != "subdir" {
        return TestResult::Fail;
    }
    if cloned.inode != 100 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cached_inode_basic() -> TestResult {
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
    if inode.inode != 42 {
        return TestResult::Fail;
    }
    if inode.size != 1024 {
        return TestResult::Fail;
    }
    if inode.mode != 0o644 {
        return TestResult::Fail;
    }
    if inode.dirty {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cached_inode_dirty() -> TestResult {
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
    if !inode.dirty {
        return TestResult::Fail;
    }
    if inode.link_count != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cached_inode_clone() -> TestResult {
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
    if cloned.inode != 10 {
        return TestResult::Fail;
    }
    if cloned.ref_count != 2 {
        return TestResult::Fail;
    }
    if !cloned.dirty {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_dirty_page_basic() -> TestResult {
    let page = DirtyPage { offset: 4096, data: alloc::vec![1, 2, 3, 4] };
    if page.offset != 4096 {
        return TestResult::Fail;
    }
    if page.data.len() != 4 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_info_basic() -> TestResult {
    let info = FileInfo {
        path: alloc::string::String::from("/test/file.txt"),
        inode: 42,
        retries: 0,
        last_attempt: 1000,
    };
    if info.path != "/test/file.txt" {
        return TestResult::Fail;
    }
    if info.inode != 42 {
        return TestResult::Fail;
    }
    if info.retries != 0 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_file_info_clone() -> TestResult {
    let info = FileInfo {
        path: alloc::string::String::from("/data/log"),
        inode: 100,
        retries: 2,
        last_attempt: 5000,
    };
    let cloned = info.clone();
    if cloned.path != "/data/log" {
        return TestResult::Fail;
    }
    if cloned.retries != 2 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_cache_statistics() -> TestResult {
    CACHE_STATS.reset();
    CACHE_STATS.hits.store(100, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.misses.store(50, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.evictions.store(10, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.writebacks.store(5, core::sync::atomic::Ordering::Relaxed);

    let (hits, misses, evictions, writebacks) = get_cache_statistics();
    if hits != 100 {
        return TestResult::Fail;
    }
    if misses != 50 {
        return TestResult::Fail;
    }
    if evictions != 10 {
        return TestResult::Fail;
    }
    if writebacks != 5 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_cache_hit_ratio() -> TestResult {
    CACHE_STATS.reset();
    CACHE_STATS.hits.store(80, core::sync::atomic::Ordering::Relaxed);
    CACHE_STATS.misses.store(20, core::sync::atomic::Ordering::Relaxed);

    let ratio = get_cache_hit_ratio();
    if !((ratio - 0.8).abs() < 0.001) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_init_all_caches() -> TestResult {
    init_all_caches();
    TestResult::Pass
}

pub(crate) fn test_clear_all_caches() -> TestResult {
    init_all_caches();
    clear_all_caches();
    TestResult::Pass
}

pub(crate) fn test_init_page_cache() -> TestResult {
    init_page_cache();
    TestResult::Pass
}

pub(crate) fn test_clear_page_cache() -> TestResult {
    init_page_cache();
    clear_page_cache();
    TestResult::Pass
}

pub(crate) fn test_get_page_cache_stats() -> TestResult {
    init_page_cache();
    let (pages, dirty, bytes) = get_page_cache_stats();
    if !(pages >= 0) {
        return TestResult::Fail;
    }
    if !(dirty >= 0) {
        return TestResult::Fail;
    }
    if !(bytes >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_init_dentry_cache() -> TestResult {
    init_dentry_cache();
    TestResult::Pass
}

pub(crate) fn test_clear_dentry_cache() -> TestResult {
    init_dentry_cache();
    clear_dentry_cache();
    TestResult::Pass
}

pub(crate) fn test_init_inode_cache() -> TestResult {
    init_inode_cache();
    TestResult::Pass
}

pub(crate) fn test_clear_inode_cache() -> TestResult {
    init_inode_cache();
    clear_inode_cache();
    TestResult::Pass
}

pub(crate) fn test_cleanup_unused_inodes() -> TestResult {
    init_inode_cache();
    let removed = cleanup_unused_inodes(10);
    if !(removed >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_update_inode_timestamps() -> TestResult {
    init_inode_cache();
    let updated = update_inode_timestamps(10);
    if !(updated >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_writeback_dirty_inodes() -> TestResult {
    init_inode_cache();
    let written = writeback_dirty_inodes(10);
    if !(written >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_full_cache_statistics() -> TestResult {
    init_all_caches();
    let stats = get_full_cache_statistics();
    if !(stats.pages_used >= 0) {
        return TestResult::Fail;
    }
    if !(stats.dirty_pages >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lookup_dentry_not_found() -> TestResult {
    init_dentry_cache();
    clear_dentry_cache();
    let result = lookup_dentry("/nonexistent/path");
    if !result.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_update_directory_entry() -> TestResult {
    init_dentry_cache();
    let entry = DirectoryEntry {
        name: alloc::string::String::from("/test/entry"),
        inode: 42,
        parent_inode: 1,
        file_type: 0,
        size: 100,
    };
    let result = update_directory_entry(&entry);
    if !result.is_ok() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_lookup_dentry_after_insert() -> TestResult {
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
    if !found.is_some() {
        return TestResult::Fail;
    }
    if found.unwrap().inode != 50 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_remove_dentry() -> TestResult {
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
    if !found.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_queue_dentry_update() -> TestResult {
    init_dentry_cache();
    let entry = DirectoryEntry {
        name: alloc::string::String::from("/test/queue"),
        inode: 70,
        parent_inode: 1,
        file_type: 0,
        size: 0,
    };
    queue_dentry_update(entry);
    TestResult::Pass
}

pub(crate) fn test_get_pending_dentry_updates() -> TestResult {
    init_dentry_cache();
    let updates = get_pending_dentry_updates();
    if !(updates.len() <= 32) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_process_inode_cache_maintenance() -> TestResult {
    init_inode_cache();
    let processed = process_inode_cache_maintenance(100);
    if !(processed >= 0) {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_cache_page() -> TestResult {
    init_page_cache();
    let data = alloc::vec![1u8, 2, 3, 4, 5, 6, 7, 8];
    cache_page(1, 0, data, false);
    TestResult::Pass
}

pub(crate) fn test_get_cached_page() -> TestResult {
    init_page_cache();
    let data = alloc::vec![10u8, 20, 30, 40];
    cache_page(2, 4096, data.clone(), false);
    let cached = get_cached_page(2, 4096);
    if !cached.is_some() {
        return TestResult::Fail;
    }
    if cached.unwrap() != data {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_cached_page_not_found() -> TestResult {
    init_page_cache();
    let cached = get_cached_page(99999, 0);
    if !cached.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_mark_page_clean() -> TestResult {
    init_page_cache();
    let data = alloc::vec![1u8, 2, 3];
    cache_page(3, 0, data, true);
    mark_page_clean(3, 0);
    TestResult::Pass
}

pub(crate) fn test_cache_inode() -> TestResult {
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
    TestResult::Pass
}

pub(crate) fn test_get_cached_inode() -> TestResult {
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
    if !cached.is_some() {
        return TestResult::Fail;
    }
    if cached.unwrap().size != 2048 {
        return TestResult::Fail;
    }
    TestResult::Pass
}

pub(crate) fn test_get_cached_inode_not_found() -> TestResult {
    init_inode_cache();
    let cached = get_cached_inode(99999);
    if !cached.is_none() {
        return TestResult::Fail;
    }
    TestResult::Pass
}
