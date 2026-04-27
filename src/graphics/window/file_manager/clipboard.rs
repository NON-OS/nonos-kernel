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

use super::constants::MAX_PATH_LEN;
use super::listing::refresh_listing;
use super::state::{
    get_current_source, get_path, CLIPBOARD_IS_CUT, CLIPBOARD_IS_DIR, CLIPBOARD_LEN,
    CLIPBOARD_PATH, FILE_ENTRIES, FILE_ENTRY_COUNT, FM_SELECTED_ITEM,
};
use super::types::{FileSource, FmResult};
use crate::fs::ramfs;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub fn copy_selected() -> FmResult {
    let selected = FM_SELECTED_ITEM.load(Ordering::Relaxed);
    if selected == 255 || selected as usize >= FILE_ENTRY_COUNT.load(Ordering::Relaxed) as usize {
        return FmResult::NotFound;
    }

    let entry = unsafe { &FILE_ENTRIES[selected as usize] };
    let name = unsafe { core::str::from_utf8_unchecked(&entry.name[..entry.name_len as usize]) };

    let path = get_path();
    let path_bytes = path.as_bytes();
    let name_bytes = name.as_bytes();

    let path_len = path_bytes.len();
    let needs_slash = !path.ends_with('/');
    let separator_len = if needs_slash { 1 } else { 0 };

    let total_len =
        match path_len.checked_add(separator_len).and_then(|v| v.checked_add(name_bytes.len())) {
            Some(len) if len <= MAX_PATH_LEN => len,
            _ => return FmResult::InvalidName,
        };

    unsafe {
        CLIPBOARD_PATH[..path_len].copy_from_slice(path_bytes);
        let mut len = path_len;

        if needs_slash {
            CLIPBOARD_PATH[len] = b'/';
            len += 1;
        }

        CLIPBOARD_PATH[len..len + name_bytes.len()].copy_from_slice(name_bytes);
    }

    CLIPBOARD_LEN.store(total_len as u8, Ordering::Relaxed);
    CLIPBOARD_IS_CUT.store(false, Ordering::Relaxed);
    CLIPBOARD_IS_DIR.store(entry.is_dir, Ordering::Relaxed);

    FmResult::Ok
}

pub fn cut_selected() -> FmResult {
    let result = copy_selected();
    if matches!(result, FmResult::Ok) {
        CLIPBOARD_IS_CUT.store(true, Ordering::Relaxed);
    }
    result
}

pub fn paste() -> FmResult {
    let clip_len = CLIPBOARD_LEN.load(Ordering::Relaxed) as usize;
    if clip_len == 0 {
        return FmResult::NotFound;
    }

    let source_path = unsafe { core::str::from_utf8_unchecked(&CLIPBOARD_PATH[..clip_len]) };

    let filename = match source_path.rfind('/') {
        Some(pos) => &source_path[pos + 1..],
        None => source_path,
    };

    let dest_path = get_path();
    let mut full_dest = String::new();
    full_dest.push_str(dest_path);
    if !dest_path.ends_with('/') {
        full_dest.push('/');
    }
    full_dest.push_str(filename);

    if source_path == full_dest {
        return FmResult::AlreadyExists;
    }

    let is_cut = CLIPBOARD_IS_CUT.load(Ordering::Relaxed);
    let is_dir = CLIPBOARD_IS_DIR.load(Ordering::Relaxed);

    let source = get_current_source();

    let result = match source {
        FileSource::Ramfs => paste_ramfs(source_path, &full_dest, is_dir, is_cut),
        FileSource::Fat32(_) => FmResult::IoError,
    };

    if matches!(result, FmResult::Ok) && is_cut {
        CLIPBOARD_LEN.store(0, Ordering::Relaxed);
    }

    result
}

fn paste_ramfs(source: &str, dest: &str, is_dir: bool, is_cut: bool) -> FmResult {
    if is_cut {
        match ramfs::rename(source, dest) {
            Ok(_) => {
                refresh_listing();
                FmResult::Ok
            }
            Err(_) => FmResult::IoError,
        }
    } else {
        if is_dir {
            match ramfs::create_dir(dest) {
                Ok(_) => {
                    refresh_listing();
                    FmResult::Ok
                }
                Err(_) => FmResult::IoError,
            }
        } else {
            match ramfs::read_file(source) {
                Ok(data) => match ramfs::write_or_create(dest, &data) {
                    Ok(_) => {
                        refresh_listing();
                        FmResult::Ok
                    }
                    Err(_) => FmResult::IoError,
                },
                Err(_) => FmResult::IoError,
            }
        }
    }
}

pub(crate) fn has_clipboard() -> bool {
    CLIPBOARD_LEN.load(Ordering::Relaxed) > 0
}
