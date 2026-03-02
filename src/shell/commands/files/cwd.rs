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

use core::str;

static mut CURRENT_DIR: [u8; 256] = [0u8; 256];
static mut CURRENT_DIR_LEN: usize = 0;

pub fn get_cwd() -> &'static str {
    // SAFETY: Single-threaded shell access
    unsafe {
        if CURRENT_DIR_LEN == 0 {
            CURRENT_DIR[..16].copy_from_slice(b"/home/anonymous\0");
            CURRENT_DIR_LEN = 15;
        }
        str::from_utf8(&CURRENT_DIR[..CURRENT_DIR_LEN]).unwrap_or("/home/anonymous")
    }
}

pub fn set_cwd(path: &str) {
    // SAFETY: Single-threaded shell access
    unsafe {
        let bytes = path.as_bytes();
        let len = bytes.len().min(255);
        CURRENT_DIR[..len].copy_from_slice(&bytes[..len]);
        CURRENT_DIR_LEN = len;
    }
}
