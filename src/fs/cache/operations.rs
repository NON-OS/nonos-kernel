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

use core::sync::atomic::{Ordering, compiler_fence};

use super::types::{CacheStats, CACHE_STATS};
use super::page_cache::{get_page_cache_stats, init_page_cache, clear_page_cache};
use super::inode_cache::{init_inode_cache, clear_inode_cache, cleanup_unused_inodes, update_inode_timestamps, writeback_dirty_inodes};
use super::dentry_cache::{init_dentry_cache, clear_dentry_cache};
use super::writeback::{init_writeback_queue, clear_writeback_queue};

pub fn get_full_cache_statistics() -> CacheStats {
    let (pages, dirty, bytes) = get_page_cache_stats();
    CacheStats {
        hits: CACHE_STATS.hits.load(Ordering::Relaxed),
        misses: CACHE_STATS.misses.load(Ordering::Relaxed),
        evictions: CACHE_STATS.evictions.load(Ordering::Relaxed),
        writebacks: CACHE_STATS.writebacks.load(Ordering::Relaxed),
        pages_used: pages,
        dirty_pages: dirty,
        bytes_cached: bytes,
    }
}

pub fn init_all_caches() {
    init_page_cache();
    init_writeback_queue();
    init_dentry_cache();
    init_inode_cache();
}

pub fn clear_all_caches() {
    clear_page_cache();
    clear_writeback_queue();
    clear_dentry_cache();
    clear_inode_cache();
    compiler_fence(Ordering::SeqCst);
}

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
