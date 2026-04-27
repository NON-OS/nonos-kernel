// NONOS Operating System
// Copyright (C) 2026 NONOS Contributors
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
// GNU Affero General Public License for more details.
// You should have received a copy of the GNU Affero General Public License
// along with this program. If not, see <https://www.gnu.org/licenses/>.

extern crate alloc;
use super::super::block_io::{block_read, block_write};
use super::super::listing::{get_fat32_dir_cluster, refresh_listing};
use super::super::state::{get_current_source, get_path, FM_CREATING_FILE, FM_CREATING_FOLDER};
use super::super::types::{FileSource, FmResult};
use crate::fs::ramfs;
use crate::storage::fat32;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub fn create_folder(name: &str) -> FmResult {
    if name.is_empty() {
        return FmResult::InvalidName;
    }
    let source = get_current_source();
    let max_len = match source {
        FileSource::Ramfs => 63,
        FileSource::Fat32(_) => 11,
    };
    if name.len() > max_len {
        return FmResult::InvalidName;
    }
    FM_CREATING_FOLDER.store(true, Ordering::Relaxed);
    let result = match source {
        FileSource::Ramfs => create_folder_ramfs(name),
        FileSource::Fat32(fs_id) => create_folder_fat32(fs_id, name),
    };
    FM_CREATING_FOLDER.store(false, Ordering::Relaxed);
    result
}

pub fn create_file(name: &str) -> FmResult {
    if name.is_empty() {
        return FmResult::InvalidName;
    }
    let source = get_current_source();
    let max_len = match source {
        FileSource::Ramfs => 63,
        FileSource::Fat32(_) => 11,
    };
    if name.len() > max_len {
        return FmResult::InvalidName;
    }
    FM_CREATING_FILE.store(true, Ordering::Relaxed);
    let result = match source {
        FileSource::Ramfs => create_file_ramfs(name),
        FileSource::Fat32(fs_id) => create_file_fat32(fs_id, name),
    };
    FM_CREATING_FILE.store(false, Ordering::Relaxed);
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

fn create_file_ramfs(name: &str) -> FmResult {
    let path = get_path();
    let mut full_path = String::new();
    full_path.push_str(path);
    if !path.ends_with('/') {
        full_path.push('/');
    }
    full_path.push_str(name);
    match ramfs::create_file(&full_path, b"") {
        Ok(_) => {
            refresh_listing();
            FmResult::Ok
        }
        Err(_) => FmResult::IoError,
    }
}

fn create_file_fat32(fs_id: u8, name: &str) -> FmResult {
    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => return FmResult::IoError,
    };
    let dir_cluster = get_fat32_dir_cluster(&fs, get_path());
    let new_entry = fat32::make_dir_entry(name.as_bytes(), false, 0, 0);
    write_fat32_entry(&fs, dir_cluster, &new_entry)
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
    if let Err(e) = init_fat32_dir(&fs, new_cluster, dir_cluster) {
        return e;
    }
    let new_entry = fat32::make_dir_entry(name.as_bytes(), true, new_cluster, 0);
    write_fat32_entry(&fs, dir_cluster, &new_entry)
}

fn init_fat32_dir(fs: &fat32::Fat32, new_cluster: u32, parent: u32) -> Result<(), FmResult> {
    let dot = fat32::make_dir_entry(b".", true, new_cluster, 0);
    let dotdot = fat32::make_dir_entry(b"..", true, parent, 0);
    let mut buf = [0u8; 512];
    unsafe {
        let d = core::slice::from_raw_parts(&dot as *const _ as *const u8, 32);
        let dd = core::slice::from_raw_parts(&dotdot as *const _ as *const u8, 32);
        buf[..32].copy_from_slice(d);
        buf[32..64].copy_from_slice(dd);
    }
    let sector = fs.cluster_to_sector(new_cluster);
    if block_write(fs.device_id, sector as u64, &buf).is_err() {
        return Err(FmResult::IoError);
    }
    Ok(())
}

fn write_fat32_entry(fs: &fat32::Fat32, dir_cluster: u32, entry: &fat32::DirEntry) -> FmResult {
    match fat32::find_free_dir_slot(fs, dir_cluster, block_read) {
        Ok(Some((_, slot_sector, slot_offset))) => {
            let mut buf = [0u8; 512];
            if block_read(fs.device_id, slot_sector as u64, &mut buf).is_err() {
                return FmResult::IoError;
            }
            unsafe {
                let eb = core::slice::from_raw_parts(entry as *const _ as *const u8, 32);
                buf[slot_offset..slot_offset + 32].copy_from_slice(eb);
            }
            if block_write(fs.device_id, slot_sector as u64, &buf).is_err() {
                return FmResult::IoError;
            }
            refresh_listing();
            FmResult::Ok
        }
        _ => FmResult::NoSpace,
    }
}
