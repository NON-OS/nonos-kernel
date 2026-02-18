// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
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

extern crate alloc;

use alloc::string::String;
use core::sync::atomic::{AtomicU64, Ordering};

pub const MAX_CACHED_PAGES: usize = 4096;
pub const PAGE_SIZE: usize = 4096;
pub const WRITEBACK_BATCH_SIZE: usize = 32;
pub const MAX_CACHED_INODES: usize = 1024;
pub const MAX_OPERATION_RETRIES: u32 = 3;

pub static CACHE_STATS: CacheStatistics = CacheStatistics::new();

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

    pub fn reset(&self) {
        self.hits.store(0, Ordering::Relaxed);
        self.misses.store(0, Ordering::Relaxed);
        self.evictions.store(0, Ordering::Relaxed);
        self.writebacks.store(0, Ordering::Relaxed);
    }
}

pub fn get_cache_statistics() -> (u64, u64, u64, u64) {
    (
        CACHE_STATS.hits.load(Ordering::Relaxed),
        CACHE_STATS.misses.load(Ordering::Relaxed),
        CACHE_STATS.evictions.load(Ordering::Relaxed),
        CACHE_STATS.writebacks.load(Ordering::Relaxed),
    )
}

pub fn get_cache_hit_ratio() -> f64 {
    CACHE_STATS.hit_ratio()
}

#[derive(Debug, Clone, Default)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub evictions: u64,
    pub writebacks: u64,
    pub pages_used: usize,
    pub dirty_pages: usize,
    pub bytes_cached: usize,
}

impl CacheStats {
    pub fn hit_ratio(&self) -> f64 {
        let total = self.hits + self.misses;
        if total == 0 {
            0.0
        } else {
            self.hits as f64 / total as f64
        }
    }
}

#[derive(Clone)]
pub struct FileInfo {
    pub path: String,
    pub inode: u64,
    pub retries: u32,
    pub last_attempt: u64,
}

pub struct DirtyPage {
    pub offset: u64,
    pub data: alloc::vec::Vec<u8>,
}

#[derive(Clone)]
pub struct DirectoryEntry {
    pub name: String,
    pub inode: u64,
    pub parent_inode: u64,
    pub file_type: u8,
    pub size: u64,
}

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
