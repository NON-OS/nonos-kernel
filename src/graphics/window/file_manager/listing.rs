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

use core::sync::atomic::Ordering;
use crate::fs::ramfs;
use crate::storage::fat32;
use super::constants::{MAX_ENTRIES, MAX_NAME_LEN};
use super::types::FileSource;
use super::state::{get_path, get_current_source, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM};
use super::block_io::block_read;

pub fn refresh_listing() {
    let source = get_current_source();
    let count = match source {
        FileSource::Ramfs => refresh_ramfs_listing(),
        FileSource::Fat32(fs_id) => refresh_fat32_listing(fs_id),
    };
    FILE_ENTRY_COUNT.store(count, Ordering::Relaxed);
    FM_SELECTED_ITEM.store(255, Ordering::Relaxed);
}

fn refresh_ramfs_listing() -> u8 {
    let path = get_path();
    let mut count = 0u8;

    if let Ok(entries) = ramfs::list_dir_entries(path) {
        for entry in entries.iter().take(MAX_ENTRIES) {
            // SAFETY: Single-threaded access
            let file_entry = unsafe { &mut FILE_ENTRIES[count as usize] };
            let name_bytes = entry.name.as_bytes();
            let len = name_bytes.len().min(MAX_NAME_LEN - 1);
            file_entry.name[..len].copy_from_slice(&name_bytes[..len]);
            file_entry.name_len = len as u8;
            file_entry.is_dir = entry.is_dir;
            file_entry.size = entry.size as u32;
            file_entry.cluster = 0;
            count += 1;
        }
    }

    count
}

fn refresh_fat32_listing(fs_id: u8) -> u8 {
    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => return 0,
    };

    let path = get_path();
    let dir_cluster = get_fat32_dir_cluster(&fs, path);

    static mut TEMP_COUNT: u8 = 0;
    // SAFETY: Single-threaded callback
    unsafe { TEMP_COUNT = 0; }

    fn collect_entry(entry: &fat32::DirEntry) -> bool {
        // SAFETY: Single-threaded callback, bounded by MAX_ENTRIES
        unsafe {
            if TEMP_COUNT as usize >= MAX_ENTRIES {
                return false;
            }

            let file_entry = &mut FILE_ENTRIES[TEMP_COUNT as usize];
            let mut name_buf = [0u8; 13];
            let len = entry.get_short_name(&mut name_buf);
            file_entry.name[..len].copy_from_slice(&name_buf[..len]);
            file_entry.name_len = len as u8;
            file_entry.is_dir = entry.is_directory();
            file_entry.size = entry.file_size;
            file_entry.cluster = entry.first_cluster();
            TEMP_COUNT += 1;
        }
        true
    }

    let _ = fat32::read_directory(&fs, dir_cluster, block_read, collect_entry);
    // SAFETY: Single-threaded access
    unsafe { TEMP_COUNT }
}

pub fn get_fat32_dir_cluster(fs: &fat32::Fat32, path: &str) -> u32 {
    if !path.starts_with("/disk/") {
        return fs.root_cluster;
    }

    let rest = &path[6..];
    if let Some(slash) = rest.find('/') {
        let subpath = &rest[slash + 1..];
        if subpath.is_empty() {
            return fs.root_cluster;
        }
        let mut cluster = fs.root_cluster;
        for component in subpath.split('/') {
            if component.is_empty() {
                continue;
            }
            if let Ok(Some(entry)) = fat32::find_file(fs, component.as_bytes(), block_read) {
                if entry.is_directory() {
                    cluster = entry.first_cluster();
                }
            }
        }
        cluster
    } else {
        fs.root_cluster
    }
}
