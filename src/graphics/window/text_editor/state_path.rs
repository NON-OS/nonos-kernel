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

use super::state::{EDITOR_FILE_PATH, EDITOR_PATH_LEN, PATH_SIZE};
use core::sync::atomic::Ordering;

pub(crate) fn set_path(path: &str) {
    let path_bytes = path.as_bytes();
    let path_len = path_bytes.len().min(PATH_SIZE - 1);
    unsafe {
        for i in 0..path_len {
            EDITOR_FILE_PATH[i] = path_bytes[i];
        }
        for i in path_len..PATH_SIZE {
            EDITOR_FILE_PATH[i] = 0;
        }
    }
    EDITOR_PATH_LEN.store(path_len, Ordering::Relaxed);
}

pub(crate) fn get_path() -> Option<&'static str> {
    let len = EDITOR_PATH_LEN.load(Ordering::Relaxed);
    if len == 0 {
        return None;
    }
    unsafe { core::str::from_utf8(&EDITOR_FILE_PATH[..len]).ok() }
}

pub(crate) fn get_buffer_slice() -> &'static [u8] {
    let len = super::state::EDITOR_LEN.load(Ordering::Relaxed);
    unsafe { &super::state::EDITOR_BUFFER[..len] }
}
