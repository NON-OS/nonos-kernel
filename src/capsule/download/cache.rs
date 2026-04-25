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
use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use spin::RwLock;

const MAX_CACHE_SIZE: usize = 256 * 1024 * 1024;

struct CacheEntry {
    data: Vec<u8>,
    accessed_at: u64,
}
struct Cache {
    entries: BTreeMap<String, CacheEntry>,
    total_size: usize,
}
static CACHE: RwLock<Option<Cache>> = RwLock::new(None);

pub fn init() {
    *CACHE.write() = Some(Cache { entries: BTreeMap::new(), total_size: 0 });
}

pub fn get(cid: &str) -> Option<Vec<u8>> {
    let mut guard = CACHE.write();
    let cache = guard.as_mut()?;
    let entry = cache.entries.get_mut(cid)?;
    entry.accessed_at = crate::time::unix_timestamp();
    Some(entry.data.clone())
}

pub fn insert(cid: &str, data: Vec<u8>) {
    let size = data.len();
    if size > MAX_CACHE_SIZE {
        return;
    }
    if let Some(cache) = CACHE.write().as_mut() {
        evict_if_needed(cache, size);
        cache.total_size += size;
        cache.entries.insert(
            String::from(cid),
            CacheEntry { data, accessed_at: crate::time::unix_timestamp() },
        );
    }
}

pub fn remove(cid: &str) {
    if let Some(cache) = CACHE.write().as_mut() {
        if let Some(entry) = cache.entries.remove(cid) {
            cache.total_size -= entry.data.len();
        }
    }
}

pub fn contains(cid: &str) -> bool {
    CACHE.read().as_ref().map(|c| c.entries.contains_key(cid)).unwrap_or(false)
}

pub fn size() -> usize {
    CACHE.read().as_ref().map(|c| c.total_size).unwrap_or(0)
}

pub fn count() -> usize {
    CACHE.read().as_ref().map(|c| c.entries.len()).unwrap_or(0)
}

fn evict_if_needed(cache: &mut Cache, needed: usize) {
    while cache.total_size + needed > MAX_CACHE_SIZE && !cache.entries.is_empty() {
        let oldest =
            cache.entries.iter().min_by_key(|(_, e)| e.accessed_at).map(|(k, _)| k.clone());
        if let Some(key) = oldest {
            if let Some(e) = cache.entries.remove(&key) {
                cache.total_size -= e.data.len();
            }
        }
    }
}
