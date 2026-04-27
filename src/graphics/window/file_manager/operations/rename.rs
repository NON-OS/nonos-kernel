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
    get_current_source, get_path, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM,
};
use super::super::types::{FileSource, FmResult};
use crate::fs::ramfs;
use crate::storage::fat32;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub fn rename_selected(new_name: &str) -> FmResult {
    if new_name.is_empty() {
        return FmResult::InvalidName;
    }
    let source = get_current_source();
    let max_len = match source {
        FileSource::Ramfs => 63,
        FileSource::Fat32(_) => 11,
    };
    if new_name.len() > max_len {
        return FmResult::InvalidName;
    }
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    if selected == 255 || selected as usize >= FILE_ENTRY_COUNT.load(Ordering::Relaxed) as usize {
        return FmResult::NotFound;
    }
    let entry = unsafe { &FILE_ENTRIES[selected as usize] };
    let old_name =
        unsafe { core::str::from_utf8_unchecked(&entry.name[..entry.name_len as usize]) };
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
    match fat32::rename_file(&fs, old_name.as_bytes(), new_name.as_bytes(), block_read, block_write)
    {
        Ok(_) => {
            refresh_listing();
            FmResult::Ok
        }
        Err(_) => FmResult::IoError,
    }
}
