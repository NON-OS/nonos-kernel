// NØNOS Operating System
// Copyright (C) 2025 NØNOS Contributors
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

//! NØNOS Filesystem Caching Layer

#![no_std]

extern crate alloc;

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use core::sync::atomic::{AtomicU64, Ordering, compiler_fence};
use spin::{Mutex, Once};

// ============================================================================
// CONFIGURATION CONSTANTS
// ============================================================================

/// Maximum pages to cache
pub const MAX_CACHED_PAGES: usize = 4096;

/// Page size in bytes
pub const PAGE_SIZE: usize = 4096;

/// Maximum operations per writeback batch
pub const WRITEBACK_BATCH_SIZE: usize = 32;

/// Maximum cached inodes
pub const MAX_CACHED_INODES: usize = 1024;

/// Maximum retries for failed operations
pub const MAX_OPERATION_RETRIES: u32 = 3;

// ============================================================================
// CACHE STATISTICS
// ============================================================================

/// Global cache statistics
pub static CACHE_STATS: CacheStatistics = CacheStatistics::new();

/// Cache performance statistics
pub struct CacheStatistics {
    pub hits: AtomicU64,
    pub misses: AtomicU64,
    pub evictions: AtomicU64,
    pub writebacks: AtomicU64,
}

impl CacheStatistics {
    pub const fn new() -> Self {
        Self {
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
            writebacks: AtomicU64::new(0),
        }
    }

    /// Get cache hit ratio (0.0 - 1.0)
    pub fn hit_ratio(&self) -> f64 {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;
        if total == 0 {
            0.0
        } else {
            hits as f64 / total as f64
        }
    }

    /// Reset all statistics
    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
        self.writebacks.store(0, Ordering::Relaxed);
    }
}

/// Get cache statistics as tuple (hits, misses, evictions, writebacks)
pub fn get_cache_statistics() -> (u64, u64, u64, u64) {
    (
        CACHE_STATS.hits.load(Ordering::Relaxed),
        CACHE_STATS.misses.load(Ordering::Relaxed),
        CACHE_STATS.evictions.load(Ordering::Relaxed),
        CACHE_STATS.writebacks.load(Ordering::Relaxed),
    )
}

/// Get cache hit ratio
pub fn get_cache_hit_ratio() -> f64 {
    CACHE_STATS.hit_ratio()
}

// ============================================================================
// PAGE CACHE
// ============================================================================

/// Global page cache singleton
static PAGE_CACHE: Once<Mutex<PageCache>> = Once::new();

/// A cached page with metadata
#[derive(Debug, Clone)]
struct CachedPage {
    file_id: u64,
    offset: u64,
    data: Vec<u8>,
    dirty: bool,
    accessed: u64,
    modified: u64,
    ref_count: u32,
}

/// LRU-based page cache
pub struct PageCache {
    pages: BTreeMap<(u64, u64), CachedPage>,
    dirty_list: Vec<(u64, u64)>,
    total_cached_bytes: usize,
    lru_counter: u64,
}

impl PageCache {
    fn new() -> Self {
        Self {
            pages: BTreeMap::new(),
            dirty_list: Vec::new(),
            total_cached_bytes: 0,
            lru_counter: 0,
        }
    }

    /// Get a page from cache, updating LRU
    pub fn get_page(&mut self, file_id: u64, offset: u64) -> Option<&CachedPage> {
        let key = (file_id, offset);
        if let Some(page) = self.pages.get_mut(&key) {
            self.lru_counter += 1;
            page.accessed = self.lru_counter;
            CACHE_STATS.hits.fetch_add(1, Ordering::Relaxed);
            return Some(page);
        }
        CACHE_STATS.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Insert or update a page in cache
    pub fn insert_page(&mut self, file_id: u64, offset: u64, data: Vec<u8>, dirty: bool) {
        let key = (file_id, offset);
        self.lru_counter += 1;

        // Evict if at capacity
        while self.pages.len() >= MAX_CACHED_PAGES {
            self.evict_lru_page();
        }

        let page = CachedPage {
            file_id,
            offset,
            data: data.clone(),
            dirty,
            accessed: self.lru_counter,
            modified: self.lru_counter,
            ref_count: 1,
        };

        self.total_cached_bytes += page.data.len();

        if dirty && !self.dirty_list.contains(&key) {
            self.dirty_list.push(key);
        }

        self.pages.insert(key, page);
    }

    /// Mark a page as dirty
    pub fn mark_dirty(&mut self, file_id: u64, offset: u64) {
        let key = (file_id, offset);
        if let Some(page) = self.pages.get_mut(&key) {
            page.dirty = true;
            self.lru_counter += 1;
            page.modified = self.lru_counter;
            if !self.dirty_list.contains(&key) {
                self.dirty_list.push(key);
            }
        }
    }

    /// Mark a page as clean after writeback
    pub fn mark_clean(&mut self, file_id: u64, offset: u64) {
        let key = (file_id, offset);
        if let Some(page) = self.pages.get_mut(&key) {
            page.dirty = false;
        }
        self.dirty_list.retain(|k| *k != key);
    }

    /// Evict the least recently used page
    fn evict_lru_page(&mut self) {
        let mut lru_key: Option<(u64, u64)> = None;
        let mut lru_time = u64::MAX;

        // First try to find clean page with no refs
        for (key, page) in &self.pages {
            if !page.dirty && page.accessed < lru_time && page.ref_count == 0 {
                lru_time = page.accessed;
                lru_key = Some(*key);
            }
        }

        // If all clean pages have refs, evict oldest dirty page
        if lru_key.is_none() {
            for (key, page) in &self.pages {
                if page.accessed < lru_time {
                    lru_time = page.accessed;
                    lru_key = Some(*key);
                }
            }
        }

        if let Some(key) = lru_key {
            if let Some(page) = self.pages.remove(&key) {
                self.total_cached_bytes = self.total_cached_bytes.saturating_sub(page.data.len());
                self.dirty_list.retain(|k| *k != key);
                CACHE_STATS.evictions.fetch_add(1, Ordering::Relaxed);
            }
        }
    }

    /// Get dirty pages for writeback
    pub fn get_dirty_pages_batch(&self, max: usize) -> Vec<(u64, u64, Vec<u8>)> {
        self.dirty_list
            .iter()
            .take(max)
            .filter_map(|key| self.pages.get(key).map(|p| (p.file_id, p.offset, p.data.clone())))
            .collect()
    }

    /// Clear all cached pages
    pub fn clear(&mut self) {
        self.pages.clear();
        self.dirty_list.clear();
        self.total_cached_bytes = 0;
        self.lru_counter = 0;
    }

    /// Get cache size statistics
    pub fn stats(&self) -> (usize, usize, usize) {
        (self.pages.len(), self.dirty_list.len(), self.total_cached_bytes)
    }
}

/// Initialize page cache
pub fn init_page_cache() {
    PAGE_CACHE.call_once(|| Mutex::new(PageCache::new()));
}

/// Dirty page info for writeback
pub struct DirtyPage {
    pub offset: u64,
    pub data: Vec<u8>,
}

/// Get all dirty pages grouped by file
pub fn get_dirty_pages() -> BTreeMap<u64, Vec<DirtyPage>> {
    init_page_cache();
    let mut result = BTreeMap::new();

    if let Some(cache) = PAGE_CACHE.get() {
        let cache_guard = cache.lock();
        for (key, page) in &cache_guard.pages {
            if page.dirty {
                let entry = result.entry(key.0).or_insert_with(Vec::new);
                entry.push(DirtyPage {
                    offset: key.1,
                    data: page.data.clone(),
                });
            }
        }
    }
    result
}

/// Mark a page as clean
pub fn mark_page_clean(file_id: u64, offset: u64) {
    init_page_cache();
    if let Some(cache) = PAGE_CACHE.get() {
        cache.lock().mark_clean(file_id, offset);
    }
}

/// Clear all page cache entries
pub fn clear_page_cache() {
    init_page_cache();
    if let Some(cache) = PAGE_CACHE.get() {
        cache.lock().clear();
    }
}

// ============================================================================
// WRITEBACK QUEUE
// ============================================================================

static WRITEBACK_QUEUE: Once<Mutex<WritebackQueue>> = Once::new();

/// File info for writeback tracking
#[derive(Clone)]
pub struct FileInfo {
    pub path: String,
    pub inode: u64,
    pub retries: u32,
    pub last_attempt: u64,
}

struct WritebackQueue {
    files: Vec<FileInfo>,
    retry_list: Vec<FileInfo>,
}

impl WritebackQueue {
    fn new() -> Self {
        Self {
            files: Vec::new(),
            retry_list: Vec::new(),
        }
    }

    fn add_file(&mut self, path: String, inode: u64) {
        if !self.files.iter().any(|f| f.inode == inode) {
            self.files.push(FileInfo {
                path,
                inode,
                retries: 0,
                last_attempt: 0,
            });
        }
    }

    fn get_pending(&self, max: usize) -> Vec<FileInfo> {
        self.files.iter().take(max).cloned().collect()
    }

    fn mark_complete(&mut self, inode: u64) {
        self.files.retain(|f| f.inode != inode);
    }

    fn schedule_retry(&mut self, file: &FileInfo) {
        if file.retries < MAX_OPERATION_RETRIES {
            let mut retry = file.clone();
            retry.retries += 1;
            retry.last_attempt = crate::time::current_ticks();
            self.retry_list.push(retry);
        }
    }

    fn clear(&mut self) {
        self.files.clear();
        self.retry_list.clear();
    }
}

/// Initialize writeback queue
pub fn init_writeback_queue() {
    WRITEBACK_QUEUE.call_once(|| Mutex::new(WritebackQueue::new()));
}

/// Get pending writeback files
pub fn get_writeback_files() -> Vec<FileInfo> {
    init_writeback_queue();
    if let Some(queue) = WRITEBACK_QUEUE.get() {
        return queue.lock().get_pending(WRITEBACK_BATCH_SIZE);
    }
    vec![]
}

/// Mark a file as clean after writeback
pub fn mark_file_clean(file: &FileInfo) {
    init_writeback_queue();
    if let Some(queue) = WRITEBACK_QUEUE.get() {
        queue.lock().mark_complete(file.inode);
    }
}

/// Schedule a file for retry
pub fn schedule_writeback_retry(file: &FileInfo) {
    init_writeback_queue();
    if let Some(queue) = WRITEBACK_QUEUE.get() {
        queue.lock().schedule_retry(file);
    }
}

/// Clear writeback queue
pub fn clear_writeback_queue() {
    init_writeback_queue();
    if let Some(queue) = WRITEBACK_QUEUE.get() {
        queue.lock().clear();
    }
}

// ============================================================================
// DENTRY CACHE
// ============================================================================

static DENTRY_CACHE: Once<Mutex<DentryCache>> = Once::new();

/// Directory entry for caching
#[derive(Clone)]
pub struct DirectoryEntry {
    pub name: String,
    pub inode: u64,
    pub parent_inode: u64,
    pub file_type: u8, // 1=file, 2=dir, 3=symlink
    pub size: u64,
}

struct DentryCache {
    entries: BTreeMap<String, DirectoryEntry>,
    pending_updates: Vec<DirectoryEntry>,
    negative_cache: BTreeMap<String, u64>,
}

impl DentryCache {
    fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            pending_updates: Vec::new(),
            negative_cache: BTreeMap::new(),
        }
    }

    fn lookup(&self, path: &str) -> Option<&DirectoryEntry> {
        self.entries.get(path)
    }

    fn insert(&mut self, path: String, entry: DirectoryEntry) {
        self.negative_cache.remove(&path);
        self.entries.insert(path, entry);
    }

    fn remove(&mut self, path: &str) {
        self.entries.remove(path);
        self.negative_cache.insert(path.into(), crate::time::current_ticks());
    }

    fn queue_update(&mut self, entry: DirectoryEntry) {
        self.pending_updates.push(entry);
    }

    fn get_pending_updates(&self, max: usize) -> Vec<DirectoryEntry> {
        self.pending_updates.iter().take(max).cloned().collect()
    }

    fn commit_update(&mut self, inode: u64) {
        self.pending_updates.retain(|e| e.inode != inode);
    }

    fn clear(&mut self) {
        self.entries.clear();
        self.pending_updates.clear();
        self.negative_cache.clear();
    }
}

/// Initialize dentry cache
pub fn init_dentry_cache() {
    DENTRY_CACHE.call_once(|| Mutex::new(DentryCache::new()));
}

/// Get pending dentry updates
pub fn get_pending_dentry_updates() -> Vec<DirectoryEntry> {
    init_dentry_cache();
    if let Some(cache) = DENTRY_CACHE.get() {
        return cache.lock().get_pending_updates(32);
    }
    vec![]
}

/// Update a directory entry
pub fn update_directory_entry(dentry: &DirectoryEntry) -> Result<(), &'static str> {
    init_dentry_cache();
    if let Some(cache) = DENTRY_CACHE.get() {
        cache.lock().insert(dentry.name.clone(), dentry.clone());
        Ok(())
    } else {
        Err("Dentry cache not initialized")
    }
}

/// Commit a dentry update
pub fn commit_dentry_update(dentry: &DirectoryEntry) {
    init_dentry_cache();
    if let Some(cache) = DENTRY_CACHE.get() {
        cache.lock().commit_update(dentry.inode);
    }
}

/// Clear dentry cache
pub fn clear_dentry_cache() {
    init_dentry_cache();
    if let Some(cache) = DENTRY_CACHE.get() {
        cache.lock().clear();
    }
}

// ============================================================================
// INODE CACHE
// ============================================================================

static INODE_CACHE: Once<Mutex<InodeCache>> = Once::new();

/// Cached inode structure
#[derive(Clone)]
pub struct CachedInode {
    pub inode: u64,
    pub size: u64,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
    pub link_count: u32,
    pub ref_count: u32,
    pub dirty: bool,
    pub accessed: u64,
}

struct InodeCache {
    inodes: BTreeMap<u64, CachedInode>,
    dirty_inodes: Vec<u64>,
    lru_counter: u64,
}

impl InodeCache {
    fn new() -> Self {
        Self {
            inodes: BTreeMap::new(),
            dirty_inodes: Vec::new(),
            lru_counter: 0,
        }
    }

    fn get(&mut self, inode: u64) -> Option<&CachedInode> {
        if let Some(cached) = self.inodes.get_mut(&inode) {
            self.lru_counter += 1;
            cached.accessed = self.lru_counter;
            return Some(cached);
        }
        None
    }

    fn insert(&mut self, cached: CachedInode) {
        if self.inodes.len() >= MAX_CACHED_INODES {
            self.evict_lru();
        }
        if cached.dirty && !self.dirty_inodes.contains(&cached.inode) {
            self.dirty_inodes.push(cached.inode);
        }
        self.inodes.insert(cached.inode, cached);
    }

    fn evict_lru(&mut self) {
        let mut lru_inode: Option<u64> = None;
        let mut lru_time = u64::MAX;

        for (id, inode) in &self.inodes {
            if inode.ref_count == 0 && !inode.dirty && inode.accessed < lru_time {
                lru_time = inode.accessed;
                lru_inode = Some(*id);
            }
        }

        if let Some(id) = lru_inode {
            self.inodes.remove(&id);
        }
    }

    fn cleanup_unused(&mut self, max: usize) -> usize {
        let to_remove: Vec<u64> = self
            .inodes
            .iter()
            .filter(|(_, i)| i.ref_count == 0 && !i.dirty)
            .take(max)
            .map(|(id, _)| *id)
            .collect();

        let removed = to_remove.len();
        for id in to_remove {
            self.inodes.remove(&id);
        }
        removed
    }

    fn update_timestamps(&mut self, max: usize) -> usize {
        let current_time = crate::time::current_ticks();
        let mut updated = 0;

        for (_, inode) in self.inodes.iter_mut().take(max) {
            if inode.dirty {
                inode.mtime = current_time;
                updated += 1;
            }
        }
        updated
    }

    fn get_dirty_inodes(&self, max: usize) -> Vec<CachedInode> {
        self.dirty_inodes
            .iter()
            .take(max)
            .filter_map(|id| self.inodes.get(id).cloned())
            .collect()
    }

    fn mark_clean(&mut self, inode: u64) {
        if let Some(cached) = self.inodes.get_mut(&inode) {
            cached.dirty = false;
        }
        self.dirty_inodes.retain(|&i| i != inode);
    }

    fn clear(&mut self) {
        self.inodes.clear();
        self.dirty_inodes.clear();
        self.lru_counter = 0;
    }
}

/// Initialize inode cache
pub fn init_inode_cache() {
    INODE_CACHE.call_once(|| Mutex::new(InodeCache::new()));
}

/// Cleanup unused inodes
pub fn cleanup_unused_inodes(max: usize) -> usize {
    init_inode_cache();
    if let Some(cache) = INODE_CACHE.get() {
        return cache.lock().cleanup_unused(max);
    }
    0
}

/// Update inode timestamps
pub fn update_inode_timestamps(max: usize) -> usize {
    init_inode_cache();
    if let Some(cache) = INODE_CACHE.get() {
        return cache.lock().update_timestamps(max);
    }
    0
}

/// Writeback dirty inodes
pub fn writeback_dirty_inodes(max: usize) -> usize {
    init_inode_cache();
    if let Some(cache) = INODE_CACHE.get() {
        let dirty = {
            let guard = cache.lock();
            guard.get_dirty_inodes(max)
        };

        let mut written = 0;
        for inode in dirty {
            cache.lock().mark_clean(inode.inode);
            written += 1;
            CACHE_STATS.writebacks.fetch_add(1, Ordering::Relaxed);
        }
        return written;
    }
    0
}

/// Clear inode cache
pub fn clear_inode_cache() {
    init_inode_cache();
    if let Some(cache) = INODE_CACHE.get() {
        cache.lock().clear();
    }
}

// ============================================================================
// UNIFIED CACHE OPERATIONS
// ============================================================================

/// Initialize all caches
pub fn init_all_caches() {
    init_page_cache();
    init_writeback_queue();
    init_dentry_cache();
    init_inode_cache();
}

/// Clear all caches (for ZeroState wipe)
pub fn clear_all_caches() {
    clear_page_cache();
    clear_writeback_queue();
    clear_dentry_cache();
    clear_inode_cache();
    compiler_fence(Ordering::SeqCst);
}

/// Process inode cache maintenance
pub fn process_inode_cache_maintenance(max_operations: usize) -> usize {
    let mut processed = cleanup_unused_inodes(max_operations);

    if processed < max_operations {
        processed += update_inode_timestamps(max_operations - processed);
    }

    if processed < max_operations {
        processed += writeback_dirty_inodes(max_operations - processed);
    }

    processed
}

// ============================================================================
// UNIT TESTS
// ============================================================================

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_statistics() {
        let stats = CacheStatistics::new();
        stats.hits.fetch_add(10, Ordering::Relaxed);
        stats.misses.fetch_add(5, Ordering::Relaxed);
        assert!((stats.hit_ratio() - 0.666).abs() < 0.01);
    }

    #[test]
    fn test_page_cache_basic() {
        init_page_cache();
        if let Some(cache) = PAGE_CACHE.get() {
            let mut guard = cache.lock();
            guard.insert_page(1, 0, vec![1, 2, 3], false);
            assert!(guard.get_page(1, 0).is_some());
            guard.clear();
            assert!(guard.get_page(1, 0).is_none());
        }
    }
}
