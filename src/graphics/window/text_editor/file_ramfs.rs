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
use super::state::*;
use crate::fs::ramfs;
use core::sync::atomic::Ordering;

pub(super) fn open(path: &str) -> bool {
    match ramfs::read_file(path) {
        Ok(data) => {
            buffer::load_content(&data);
            set_path(path);
            let lang = super::syntax::detect_language(path.as_bytes());
            super::syntax::set_language(lang);
            EDITOR_MODIFIED.store(false, Ordering::Relaxed);
            EDITOR_STATUS.store(STATUS_OPENED, Ordering::Relaxed);
            true
        }
        Err(_) => {
            EDITOR_STATUS.store(STATUS_ERROR, Ordering::Relaxed);
            false
        }
    }
}

pub(super) fn save(path: &str) -> bool {
    let data = get_buffer_slice();
    let result = if ramfs::exists(path) {
        ramfs::write_file(path, data)
    } else {
        ramfs::create_file(path, data)
    };
    match result {
        Ok(()) => {
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
