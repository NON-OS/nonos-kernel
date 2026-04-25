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

use super::file_util::is_disk_path;
use super::state::*;
use crate::fs::ramfs;
use alloc::string::String;
use core::sync::atomic::Ordering;

pub(super) fn new_file() {
    reset_state();
    super::syntax::set_language(super::syntax::Language::Plain);
    EDITOR_STATUS.store(STATUS_NEW, Ordering::Relaxed);
}

pub(super) fn open_file(path: &str) -> bool {
    if is_disk_path(path) {
        super::file_fat32::open(path)
    } else {
        super::file_ramfs::open(path)
    }
}

pub(super) fn save_file() -> bool {
    let path = match get_path() {
        Some(p) if !p.is_empty() => p,
        _ => return save_new_file(),
    };
    if is_disk_path(path) {
        super::file_fat32::save(path)
    } else {
        super::file_ramfs::save(path)
    }
}

fn save_new_file() -> bool {
    let path = generate_unique_filename();
    set_path(&path);
    super::file_ramfs::save(&path)
}

fn generate_unique_filename() -> String {
    let base = "/ram/untitled";
    let ext = ".txt";
    if !ramfs::exists(&format_path(base, 0, ext)) {
        return format_path(base, 0, ext);
    }
    for i in 1..100 {
        let path = format_path_num(base, i, ext);
        if !ramfs::exists(&path) {
            return path;
        }
    }
    format_path_num(base, 99, ext)
}

fn format_path(base: &str, _n: u32, ext: &str) -> String {
    let mut s = String::new();
    s.push_str(base);
    s.push_str(ext);
    s
}

fn format_path_num(base: &str, n: u32, ext: &str) -> String {
    let mut s = String::new();
    s.push_str(base);
    s.push('_');
    if n >= 10 {
        s.push((b'0' + (n / 10) as u8) as char);
    }
    s.push((b'0' + (n % 10) as u8) as char);
    s.push_str(ext);
    s
}

pub(super) fn save_file_as(path: &str) -> bool {
    set_path(path);
    save_file()
}

pub(super) fn close_file() {
    reset_state();
}

pub(crate) fn is_modified() -> bool {
    EDITOR_MODIFIED.load(Ordering::Relaxed)
}
