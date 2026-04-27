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

use alloc::string::{String, ToString};
use core::sync::atomic::Ordering;

use crate::fs::fd::error::FdResult;
use crate::fs::fd::types::MAX_FD;

use super::core::{get_entry_read, is_stdio, validate_fd_range, FD_TABLE, NEXT_FD};

pub fn fd_is_valid(fd: i32) -> bool {
    if fd < 0 || fd > MAX_FD {
        return false;
    }
    if is_stdio(fd) {
        return true;
    }
    let table = FD_TABLE.read();
    table.contains_key(&fd)
}

pub fn fd_get_path(fd: i32) -> FdResult<String> {
    validate_fd_range(fd)?;

    match fd {
        0 => Ok("/dev/stdin".to_string()),
        1 => Ok("/dev/stdout".to_string()),
        2 => Ok("/dev/stderr".to_string()),
        _ => get_entry_read(fd, |entry| Ok(entry.path.clone())),
    }
}

pub fn fd_get_offset(fd: i32) -> FdResult<usize> {
    get_entry_read(fd, |entry| Ok(entry.offset))
}

pub fn fd_stats() -> (usize, i32) {
    let table = FD_TABLE.read();
    let count = table.len();
    let next = NEXT_FD.load(Ordering::Relaxed);
    (count, next)
}
