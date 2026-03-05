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

use alloc::string::String;
use alloc::vec::Vec;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use spin::Mutex;
use super::error::{NpkgError, NpkgResult};

const CACHE_DIR: &str = "/var/cache/npkg";
const MAX_CACHE_SIZE: u64 = 512 * 1024 * 1024;
const MAX_CACHE_AGE: u64 = 7 * 24 * 60 * 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CachePolicy {
    KeepAll,
    KeepLatest,
    KeepInstalled,
    KeepNone,
}

impl Default for CachePolicy {
    fn default() -> Self {
        Self::KeepLatest
    }
}

#[derive(Debug, Clone)]
pub struct CacheStats {
    pub total_size: u64,
    pub package_count: u32,
    pub oldest_entry: u64,
    pub newest_entry: u64,
}

struct CacheManager {
    policy: CachePolicy,
    max_size: u64,
    max_age: u64,
    current_size: AtomicU64,
    entry_count: AtomicU64,
}

impl CacheManager {
    fn new() -> Self {
        Self {
            policy: CachePolicy::default(),
            max_size: MAX_CACHE_SIZE,
            max_age: MAX_CACHE_AGE,
            current_size: AtomicU64::new(0),
            entry_count: AtomicU64::new(0),
        }
    }
}

static CACHE_MANAGER: Mutex<Option<CacheManager>> = Mutex::new(None);
static CACHE_INITIALIZED: AtomicBool = AtomicBool::new(false);

pub fn init_cache() -> NpkgResult<()> {
    if CACHE_INITIALIZED.swap(true, Ordering::SeqCst) {
        return Ok(());
    }

    let _ = crate::fs::mkdir("/var", 0o755);
    let _ = crate::fs::mkdir("/var/cache", 0o755);
    let _ = crate::fs::mkdir(CACHE_DIR, 0o755);

    let manager = CacheManager::new();

    if let Ok(entries) = list_cache_entries() {
        let mut total_size = 0u64;
        for (_, size, _) in &entries {
            total_size += size;
        }
        manager.current_size.store(total_size, Ordering::SeqCst);
        manager.entry_count.store(entries.len() as u64, Ordering::SeqCst);
    }

    let mut guard = CACHE_MANAGER.lock();
    *guard = Some(manager);

    Ok(())
}

pub fn get_cache_dir() -> String {
    String::from(CACHE_DIR)
}

pub fn is_cached(filename: &str) -> bool {
    let path = alloc::format!("{}/{}", CACHE_DIR, filename);
    crate::fs::vfs::get_vfs()
        .map(|vfs| vfs.exists(&path))
        .unwrap_or(false)
}

pub fn get_cached_path(filename: &str) -> NpkgResult<String> {
    let path = alloc::format!("{}/{}", CACHE_DIR, filename);

    if !is_cached(filename) {
        return Err(NpkgError::IoError(alloc::format!("not cached: {}", filename)));
    }

    Ok(path)
}

pub fn add_to_cache(filename: &str, data: &[u8]) -> NpkgResult<String> {
    let path = alloc::format!("{}/{}", CACHE_DIR, filename);

    crate::fs::nonos_vfs::vfs_write_file(&path, data)
        .map_err(|_| NpkgError::IoError(String::from("cache write failed")))?;

    let guard = CACHE_MANAGER.lock();
    if let Some(ref manager) = *guard {
        manager.current_size.fetch_add(data.len() as u64, Ordering::SeqCst);
        manager.entry_count.fetch_add(1, Ordering::SeqCst);
    }

    Ok(path)
}

pub fn remove_from_cache(filename: &str) -> NpkgResult<()> {
    let path = alloc::format!("{}/{}", CACHE_DIR, filename);

    let size = crate::fs::vfs::get_vfs()
        .and_then(|vfs| vfs.stat(&path).ok())
        .map(|meta| meta.size)
        .unwrap_or(0);

    crate::fs::unlink(&path)
        .map_err(|_| NpkgError::IoError(String::from("cache delete failed")))?;

    let guard = CACHE_MANAGER.lock();
    if let Some(ref manager) = *guard {
        manager.current_size.fetch_sub(size, Ordering::SeqCst);
        manager.entry_count.fetch_sub(1, Ordering::SeqCst);
    }

    Ok(())
}

pub fn clear_cache() -> NpkgResult<u64> {
    let entries = list_cache_entries()?;
    let mut freed = 0u64;

    for (filename, size, _) in entries {
        if let Ok(()) = remove_from_cache(&filename) {
            freed += size;
        }
    }

    let guard = CACHE_MANAGER.lock();
    if let Some(ref manager) = *guard {
        manager.current_size.store(0, Ordering::SeqCst);
        manager.entry_count.store(0, Ordering::SeqCst);
    }

    Ok(freed)
}

pub fn clean_old_entries() -> NpkgResult<u64> {
    let guard = CACHE_MANAGER.lock();
    let max_age = guard.as_ref().map(|m| m.max_age).unwrap_or(MAX_CACHE_AGE);
    drop(guard);

    let now = crate::time::unix_timestamp();
    let cutoff = now.saturating_sub(max_age);

    let entries = list_cache_entries()?;
    let mut freed = 0u64;

    for (filename, size, mtime) in entries {
        if mtime < cutoff {
            if let Ok(()) = remove_from_cache(&filename) {
                freed += size;
            }
        }
    }

    Ok(freed)
}

pub fn enforce_size_limit() -> NpkgResult<u64> {
    let guard = CACHE_MANAGER.lock();
    let max_size = guard.as_ref().map(|m| m.max_size).unwrap_or(MAX_CACHE_SIZE);
    let current_size = guard.as_ref()
        .map(|m| m.current_size.load(Ordering::SeqCst))
        .unwrap_or(0);
    drop(guard);

    if current_size <= max_size {
        return Ok(0);
    }

    let mut entries = list_cache_entries()?;
    entries.sort_by_key(|(_, _, mtime)| *mtime);

    let mut freed = 0u64;
    let mut remaining = current_size;

    for (filename, size, _) in entries {
        if remaining <= max_size {
            break;
        }

        if let Ok(()) = remove_from_cache(&filename) {
            freed += size;
            remaining -= size;
        }
    }

    Ok(freed)
}

fn list_cache_entries() -> NpkgResult<Vec<(String, u64, u64)>> {
    let vfs = crate::fs::vfs::get_vfs()
        .ok_or_else(|| NpkgError::InternalError(String::from("no vfs")))?;

    let entries = vfs.list_dir(CACHE_DIR)
        .map_err(|_| NpkgError::IoError(String::from("readdir failed")))?;

    let mut result = Vec::new();

    for name in entries {
        if name.starts_with('.') {
            continue;
        }

        let path = alloc::format!("{}/{}", CACHE_DIR, name);

        if let Ok(meta) = vfs.stat(&path) {
            result.push((name, meta.size, meta.mtime));
        }
    }

    Ok(result)
}

pub fn cache_stats() -> Option<CacheStats> {
    let guard = CACHE_MANAGER.lock();
    let manager = guard.as_ref()?;

    let total_size = manager.current_size.load(Ordering::SeqCst);
    let package_count = manager.entry_count.load(Ordering::SeqCst) as u32;

    let entries = list_cache_entries().ok()?;

    let oldest = entries.iter().map(|(_, _, t)| *t).min().unwrap_or(0);
    let newest = entries.iter().map(|(_, _, t)| *t).max().unwrap_or(0);

    Some(CacheStats {
        total_size,
        package_count,
        oldest_entry: oldest,
        newest_entry: newest,
    })
}

pub fn set_cache_policy(policy: CachePolicy) {
    let mut guard = CACHE_MANAGER.lock();
    if let Some(ref mut manager) = *guard {
        manager.policy = policy;
    }
}

pub fn set_max_cache_size(size: u64) {
    let mut guard = CACHE_MANAGER.lock();
    if let Some(ref mut manager) = *guard {
        manager.max_size = size;
    }
}

pub fn set_max_cache_age(seconds: u64) {
    let mut guard = CACHE_MANAGER.lock();
    if let Some(ref mut manager) = *guard {
        manager.max_age = seconds;
    }
}

pub fn get_cache_policy() -> CachePolicy {
    let guard = CACHE_MANAGER.lock();
    guard.as_ref().map(|m| m.policy).unwrap_or_default()
}
