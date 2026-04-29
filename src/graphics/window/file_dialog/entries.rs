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

use super::state::{DirEntry, ENTRIES, ENTRY_COUNT, MAX_ENTRIES, MAX_NAME};
use crate::fs::vfs::{get_vfs, FileType};
use core::sync::atomic::Ordering;

pub(super) fn refresh_entries(path: &[u8]) {
    let path_str = core::str::from_utf8(path).unwrap_or("/");
    let mut count = 1usize;

    unsafe {
        ENTRIES[0] = make_entry(b"..", true, 0);

        if let Some(vfs) = get_vfs() {
            if let Ok(names) = vfs.list_dir(path_str) {
                for name in names.iter().take(MAX_ENTRIES - 1) {
                    if count >= MAX_ENTRIES {
                        break;
                    }
                    let full_path = if path_str == "/" {
                        alloc::format!("/{}", name)
                    } else {
                        alloc::format!("{}/{}", path_str.trim_end_matches('/'), name)
                    };
                    let (is_dir, size) = if let Ok(meta) = vfs.stat(&full_path) {
                        (meta.file_type == FileType::Directory, meta.size)
                    } else {
                        (false, 0)
                    };
                    ENTRIES[count] = make_entry(name.as_bytes(), is_dir, size);
                    count += 1;
                }
            }
        }
    }

    ENTRY_COUNT.store(count, Ordering::Relaxed);
    sort_entries();
}

fn make_entry(name: &[u8], is_dir: bool, size: u64) -> DirEntry {
    let mut entry = DirEntry::empty();
    entry.name_len = name.len().min(MAX_NAME);
    for i in 0..entry.name_len {
        entry.name[i] = name[i];
    }
    entry.is_dir = is_dir;
    entry.size = size;
    entry
}

fn sort_entries() {
    let count = ENTRY_COUNT.load(Ordering::Relaxed);
    if count <= 2 {
        return;
    }
    unsafe {
        for i in 1..count {
            for j in i + 1..count {
                let swap = should_swap(&ENTRIES[i], &ENTRIES[j]);
                if swap {
                    let tmp = ENTRIES[i];
                    ENTRIES[i] = ENTRIES[j];
                    ENTRIES[j] = tmp;
                }
            }
        }
    }
}

fn should_swap(a: &DirEntry, b: &DirEntry) -> bool {
    if a.is_dir != b.is_dir {
        return !a.is_dir;
    }
    let a_name = &a.name[..a.name_len];
    let b_name = &b.name[..b.name_len];
    a_name > b_name
}

pub(super) fn get_entry(idx: usize) -> Option<&'static DirEntry> {
    let count = ENTRY_COUNT.load(Ordering::Relaxed);
    if idx < count {
        unsafe { Some(&ENTRIES[idx]) }
    } else {
        None
    }
}

pub(super) fn get_entry_count() -> usize {
    ENTRY_COUNT.load(Ordering::Relaxed)
}
