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

use crate::fs::fd::table::{fd_open, fd_open_raw, fd_close};

pub fn open_file_syscall(pathname: *const u8, flags: i32, _mode: u32) -> Option<i32> {
    fd_open_raw(pathname, flags).ok()
}

pub fn open_file_create(path: &str, flags: i32, _mode: u32) -> Option<i32> {
    fd_open(path, flags).ok()
}

pub fn close_file_descriptor(fd: i32) -> bool {
    fd_close(fd).is_ok()
}
