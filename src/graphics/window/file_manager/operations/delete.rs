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
use super::super::listing::refresh_listing;
use super::super::state::{
    get_current_source, get_path, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_DELETING, FM_SELECTED_ITEM,
};
use super::super::types::{FileSource, FmResult};
use crate::fs::ramfs;
use crate::storage::fat32;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub fn delete_selected() -> FmResult {
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    if selected == 255 || selected as usize >= FILE_ENTRY_COUNT.load(Ordering::Relaxed) as usize {
        return FmResult::NotFound;
    }
    FM_DELETING.store(true, Ordering::Relaxed);
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
