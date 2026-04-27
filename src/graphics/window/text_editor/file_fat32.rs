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

use super::buffer;
use super::file_util::{block_read, block_write, parse_disk_path};
use super::state::*;
use crate::storage::fat32;
use core::sync::atomic::Ordering;

pub(super) fn open(path: &str) -> bool {
    let (fs_id, filename) = match parse_disk_path(path) {
        Some(p) => p,
        None => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };
    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };
    let entry = match fat32::find_file(&fs, filename.as_bytes(), block_read) {
        Ok(Some(e)) => e,
        _ => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };
    let mut buf = [0u8; BUFFER_SIZE];
    let n = match fat32::read_file(&fs, &entry, &mut buf, block_read) {
        Ok(n) => n,
        Err(_) => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };
    buffer::load_content(&buf[..n]);
    set_path(path);
    let lang = super::syntax::detect_language(path.as_bytes());
    super::syntax::set_language(lang);
    EDITOR_MODIFIED.store(false, Ordering::Relaxed);
    EDITOR_STATUS.store(STATUS_OPENED, Ordering::Relaxed);
    true
}

pub(super) fn save(path: &str) -> bool {
    let (fs_id, filename) = match parse_disk_path(path) {
        Some(p) => p,
        None => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };
    let fs = match fat32::get_fs(fs_id) {
        Some(f) => f,
        None => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            return false;
        }
    };
    let data = get_buffer_slice();
    let result = match fat32::find_file(&fs, filename.as_bytes(), block_read) {
        Ok(Some(mut e)) => {
            fat32::update_file(&fs, &mut e, fs.root_cluster, data, block_read, block_write)
        }
        _ => fat32::create_file(
            &fs,
            fs.root_cluster,
            filename.as_bytes(),
            data,
            block_read,
            block_write,
        ),
    };
    match result {
        Ok(_) => {
            EDITOR_MODIFIED.store(false, Ordering::Relaxed);
            EDITOR_STATUS.store(STATUS_SAVED, Ordering::Relaxed);
            true
        }
        Err(_) => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            false
        }
    }
}
