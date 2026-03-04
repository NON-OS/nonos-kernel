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
use core::sync::atomic::Ordering;
use crate::fs::ramfs;
use crate::storage::fat32;
use super::types::{FileSource, FmResult};
use super::state::{get_path, get_current_source, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM, FM_CREATING_FOLDER, FM_DELETING};
use super::listing::{refresh_listing, get_fat32_dir_cluster};
use super::block_io::{block_read, block_write};

pub fn create_folder(name: &str) -> FmResult {
    if name.is_empty() || name.len() > 11 {
        return FmResult::InvalidName;
    }

    FM_CREATING_FOLDER.store(true, Ordering::Relaxed);
    let source = get_current_source();

    let result = match source {
        FileSource::Ramfs => create_folder_ramfs(name),
        FileSource::Fat32(fs_id) => create_folder_fat32(fs_id, name),
    };
    FM_CREATING_FOLDER.store(false, Ordering::Relaxed);
    result
}

fn create_folder_ramfs(name: &str) -> FmResult {
    let path = get_path();
    let mut full_path = String::new();
    full_path.push_str(path);
    if !path.ends_with('/') {
        full_path.push('/');
    }
    full_path.push_str(name);

    match ramfs::create_dir(&full_path) {
        Ok(_) => {
            refresh_listing();
            FmResult::Ok
        }
        Err(_) => FmResult::IoError,
    }
}

fn create_folder_fat32(fs_id: u8, name: &str) -> FmResult {
    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => return FmResult::IoError,
    };

    let dir_cluster = get_fat32_dir_cluster(&fs, get_path());

    let new_cluster = match fat32::allocate_cluster_chain(&fs, 1, block_read, block_write) {
        Ok(Some(c)) => c,
        Ok(None) => return FmResult::NoSpace,
        Err(_) => return FmResult::IoError,
    };

    let dot_entry = fat32::make_dir_entry(b".", true, new_cluster, 0);
    let dotdot_entry = fat32::make_dir_entry(b"..", true, dir_cluster, 0);

    let mut dir_buf = [0u8; 512];
    // SAFETY: DirEntry is 32 bytes
    unsafe {
        let dot_bytes = core::slice::from_raw_parts(
            &dot_entry as *const _ as *const u8,
            core::mem::size_of::<fat32::DirEntry>()
        );
        let dotdot_bytes = core::slice::from_raw_parts(
            &dotdot_entry as *const _ as *const u8,
            core::mem::size_of::<fat32::DirEntry>()
        );
        dir_buf[..32].copy_from_slice(dot_bytes);
        dir_buf[32..64].copy_from_slice(dotdot_bytes);
    }

    let sector = fs.cluster_to_sector(new_cluster);
    if block_write(fs.device_id, sector as u64, &dir_buf).is_err() {
        return FmResult::IoError;
    }

    let new_entry = fat32::make_dir_entry(name.as_bytes(), true, new_cluster, 0);

    match fat32::find_free_dir_slot(&fs, dir_cluster, block_read) {
        Ok(Some((_cluster, slot_sector, slot_offset))) => {
            let mut sector_buf = [0u8; 512];
            if block_read(fs.device_id, slot_sector as u64, &mut sector_buf).is_err() {
                return FmResult::IoError;
            }

            // SAFETY: DirEntry is 32 bytes, slot_offset is bounded
            unsafe {
                let entry_bytes = core::slice::from_raw_parts(
                    &new_entry as *const _ as *const u8,
                    32
                );
                sector_buf[slot_offset..slot_offset + 32].copy_from_slice(entry_bytes);
            }

            if block_write(fs.device_id, slot_sector as u64, &sector_buf).is_err() {
                return FmResult::IoError;
            }

            refresh_listing();
            FmResult::Ok
        }
        _ => FmResult::NoSpace,
    }
}

pub fn delete_selected() -> FmResult {
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    if selected == 255 || selected as usize >= FILE_ENTRY_COUNT.load(Ordering::Relaxed) as usize {
        return FmResult::NotFound;
    }

    FM_DELETING.store(true, Ordering::Relaxed);

    // SAFETY: bounds checked, single-threaded
    let entry = unsafe { &FILE_ENTRIES[selected as usize] };
    let name = unsafe { core::str::from_utf8_unchecked(&entry.name[..entry.name_len as usize]) };

    let source = get_current_source();

    let result = match source {
        FileSource::Ramfs => delete_ramfs(name),
        FileSource::Fat32(fs_id) => delete_fat32(fs_id, name),
    };

    FM_DELETING.store(false, Ordering::Relaxed);
    result
}

fn delete_ramfs(name: &str) -> FmResult {
    let path = get_path();
    let mut full_path = String::new();
    full_path.push_str(path);
    if !path.ends_with('/') {
        full_path.push('/');
    }
    full_path.push_str(name);

    match ramfs::delete(&full_path) {
        Ok(_) => {
            refresh_listing();
            FmResult::Ok
        }
        Err(_) => FmResult::IoError,
    }
}

fn delete_fat32(fs_id: u8, name: &str) -> FmResult {
    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => return FmResult::IoError,
    };

    match fat32::delete_file(&fs, name.as_bytes(), block_read, block_write) {
        Ok(_) => {
            refresh_listing();
            FmResult::Ok
        }
        Err(_) => FmResult::IoError,
    }
}

pub fn rename_selected(new_name: &str) -> FmResult {
    if new_name.is_empty() || new_name.len() > 11 {
        return FmResult::InvalidName;
    }

    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    if selected == 255 || selected as usize >= FILE_ENTRY_COUNT.load(Ordering::Relaxed) as usize {
        return FmResult::NotFound;
    }

    // SAFETY: bounds checked, single-threaded
    let entry = unsafe { &FILE_ENTRIES[selected as usize] };
    let old_name = unsafe { core::str::from_utf8_unchecked(&entry.name[..entry.name_len as usize]) };

    let source = get_current_source();

    match source {
        FileSource::Ramfs => rename_ramfs(old_name, new_name),
        FileSource::Fat32(fs_id) => rename_fat32(fs_id, old_name, new_name),
    }
}

fn rename_ramfs(old_name: &str, new_name: &str) -> FmResult {
    let path = get_path();
    let mut old_path = String::new();
    old_path.push_str(path);
    if !path.ends_with('/') {
        old_path.push('/');
    }
    old_path.push_str(old_name);

    let mut new_path = String::new();
    new_path.push_str(path);
    if !path.ends_with('/') {
        new_path.push('/');
    }
    new_path.push_str(new_name);

    match ramfs::rename(&old_path, &new_path) {
        Ok(_) => {
            refresh_listing();
            FmResult::Ok
        }
        Err(_) => FmResult::IoError,
    }
}

fn rename_fat32(fs_id: u8, old_name: &str, new_name: &str) -> FmResult {
    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => return FmResult::IoError,
    };

    match fat32::rename_file(&fs, old_name.as_bytes(), new_name.as_bytes(), block_read, block_write) {
        Ok(_) => {
            refresh_listing();
            FmResult::Ok
        }
        Err(_) => FmResult::IoError,
    }
}
