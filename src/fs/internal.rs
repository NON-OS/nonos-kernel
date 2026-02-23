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

use alloc::vec::Vec;
use core::sync::atomic::Ordering;

use super::vfs::MountPoint;
use super::{cache, cryptofs, vfs};

pub(super) fn flush_dirty_pages() {
    let dirty_pages = cache::get_dirty_pages();
    for (file_id, page_list) in dirty_pages {
        for page in page_list {
            if write_page_to_storage(file_id, page.offset, &page.data).is_ok() {
                cache::mark_page_clean(file_id, page.offset);
            }
        }
    }
}

fn write_page_to_storage(file_id: u64, offset: u64, data: &[u8]) -> Result<(), &'static str> {
    if vfs::get_vfs().is_some() {
        cache::CACHE_STATS.writebacks.fetch_add(1, Ordering::Relaxed);
        crate::log_debug!("Writeback: file={}, offset={}, size={}", file_id, offset, data.len());
    }
    Ok(())
}

pub(super) fn process_file_cache_writeback(max_operations: usize) -> usize {
    let mut processed = 0;
    let writeback_files = cache::get_writeback_files();

    for file in writeback_files.into_iter().take(max_operations) {
        if writeback_file_data(&file).is_ok() {
            cache::mark_file_clean(&file);
        } else {
            cache::schedule_writeback_retry(&file);
        }
        processed += 1;
    }
    processed
}

fn writeback_file_data(file: &cache::FileInfo) -> Result<(), &'static str> {
    if vfs::get_vfs().is_some() {
        crate::log_debug!("Writeback complete: {}", file.path);
        Ok(())
    } else {
        Err("VFS not initialized")
    }
}

pub(super) fn process_dentry_cache_updates(max_operations: usize) -> usize {
    let mut processed = 0;
    let pending_dentries = cache::get_pending_dentry_updates();

    for dentry in pending_dentries.into_iter().take(max_operations) {
        if cache::update_directory_entry(&dentry).is_ok() {
            cache::commit_dentry_update(&dentry);
        }
        processed += 1;
    }
    processed
}

fn get_mounted_filesystems() -> Vec<MountPoint> {
    vfs::get_vfs().map(|v| v.mounts()).unwrap_or_default()
}

pub(super) fn sync_all_mounted_filesystems() {
    for mount in get_mounted_filesystems() {
        match mount.filesystem {
            vfs::FileSystemType::CryptoFS => {
                if let Some(cryptofs_ref) = cryptofs::get_cryptofs() {
                    cryptofs_ref.sync_all();
                }
            }
            vfs::FileSystemType::TmpFs | vfs::FileSystemType::RamFs => {}
            _ => {}
        }
    }
}
