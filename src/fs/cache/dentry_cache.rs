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

use alloc::{collections::BTreeMap, string::String, vec, vec::Vec};
use spin::{Mutex, Once};

use super::types::DirectoryEntry;

static DENTRY_CACHE: Once<Mutex<DentryCache>> = Once::new();

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

pub fn init_dentry_cache() {
    DENTRY_CACHE.call_once(|| Mutex::new(DentryCache::new()));
}

pub fn get_pending_dentry_updates() -> Vec<DirectoryEntry> {
    init_dentry_cache();
    if let Some(cache) = DENTRY_CACHE.get() {
        return cache.lock().get_pending_updates(32);
    }
    vec![]
}

pub fn update_directory_entry(dentry: &DirectoryEntry) -> Result<(), &'static str> {
    init_dentry_cache();
    if let Some(cache) = DENTRY_CACHE.get() {
        cache.lock().insert(dentry.name.clone(), dentry.clone());
        Ok(())
    } else {
        Err("Dentry cache not initialized")
    }
}

pub fn commit_dentry_update(dentry: &DirectoryEntry) {
    init_dentry_cache();
    if let Some(cache) = DENTRY_CACHE.get() {
        cache.lock().commit_update(dentry.inode);
    }
}

pub fn clear_dentry_cache() {
    init_dentry_cache();
    if let Some(cache) = DENTRY_CACHE.get() {
        cache.lock().clear();
    }
}
