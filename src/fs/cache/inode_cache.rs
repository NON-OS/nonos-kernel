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

use alloc::{collections::BTreeMap, vec::Vec};
use core::sync::atomic::Ordering;
use spin::{Mutex, Once};

use super::types::{CACHE_STATS, CachedInode, MAX_CACHED_INODES};

static INODE_CACHE: Once<Mutex<InodeCache>> = Once::new();

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

pub fn init_inode_cache() {
    INODE_CACHE.call_once(|| Mutex::new(InodeCache::new()));
}

pub fn cleanup_unused_inodes(max: usize) -> usize {
    init_inode_cache();
    if let Some(cache) = INODE_CACHE.get() {
        return cache.lock().cleanup_unused(max);
    }
    0
}

pub fn update_inode_timestamps(max: usize) -> usize {
    init_inode_cache();
    if let Some(cache) = INODE_CACHE.get() {
        return cache.lock().update_timestamps(max);
    }
    0
}

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

pub fn clear_inode_cache() {
    init_inode_cache();
    if let Some(cache) = INODE_CACHE.get() {
        cache.lock().clear();
    }
}
