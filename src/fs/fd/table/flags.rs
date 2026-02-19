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

use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::types::{O_RDONLY, O_WRONLY, O_APPEND, O_NONBLOCK};

use super::core::{validate_fd_range, is_stdio, get_entry_read, get_entry_write};

pub fn fd_set_cloexec(fd: i32, cloexec: bool) -> FdResult<()> {
    get_entry_write(fd, |entry| {
        entry.cloexec = cloexec;
        Ok(())
    })
}

pub fn fd_get_cloexec(fd: i32) -> FdResult<bool> {
    get_entry_read(fd, |entry| Ok(entry.cloexec))
}

pub fn fd_get_flags(fd: i32) -> FdResult<i32> {
    validate_fd_range(fd)?;

    match fd {
        0 => Ok(O_RDONLY),
        1 | 2 => Ok(O_WRONLY),
        _ => get_entry_read(fd, |entry| Ok(entry.flags)),
    }
}

pub fn fd_set_flags(fd: i32, flags: i32) -> FdResult<()> {
    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    const MODIFIABLE_FLAGS: i32 = O_APPEND | O_NONBLOCK;

    get_entry_write(fd, |entry| {
        entry.flags = (entry.flags & !MODIFIABLE_FLAGS) | (flags & MODIFIABLE_FLAGS);
        Ok(())
    })
}

pub fn fd_set_nonblocking(fd: i32, nonblocking: bool) -> FdResult<()> {
    if is_stdio(fd) {
        return Ok(());
    }

    get_entry_write(fd, |entry| {
        if nonblocking {
            entry.flags |= O_NONBLOCK;
        } else {
            entry.flags &= !O_NONBLOCK;
        }
        Ok(())
    })
}
