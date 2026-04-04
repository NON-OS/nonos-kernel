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

use super::stats::WORKER_STATS;

pub(super) fn flush_page_cache(_start_page: u64, count: u64) {
    let _ = crate::fs::cache::writeback_dirty_inodes(count as usize);
}

pub(super) fn reclaim_memory(target_pages: u64) {
    let reclaimed = crate::fs::cache::cleanup_unused_inodes(target_pages as usize);
    WORKER_STATS.lock().pages_reclaimed += reclaimed as u64;
}

pub(super) fn compact_memory() {
    let _ = crate::fs::cache::process_inode_cache_maintenance(64);
    WORKER_STATS.lock().compactions += 1;
}

pub(super) fn sync_filesystem() {
    let _ = crate::fs::sync_all();
}

pub(super) fn process_deferred_free() {
    crate::fs::clear_all_caches();
}

pub(super) fn update_system_stats() {
    let _stats = crate::fs::get_full_cache_statistics();
}

pub(super) fn reap_zombie_processes() {
    WORKER_STATS.lock().zombies_reaped += 1;
}

pub(super) fn flush_dirty_buffers() {
    let _ = crate::fs::cache::writeback_dirty_inodes(32);
    WORKER_STATS.lock().buffers_flushed += 1;
}

pub(super) fn execute_delayed_work(id: u64) {
    match id {
        1 => sync_filesystem(),
        2 => compact_memory(),
        3 => update_system_stats(),
        _ => {}
    }
}
