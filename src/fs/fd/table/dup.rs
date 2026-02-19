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

use alloc::string::ToString;

use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::types::{OpenFile, MAX_FD, RESERVED_FDS, O_RDONLY, O_WRONLY};

use super::core::{FD_TABLE, validate_fd_range, is_stdio, fd_is_valid, fd_close};

pub fn fd_dup_min(old_fd: i32, min_fd: i32) -> FdResult<i32> {
    validate_fd_range(old_fd)?;

    if min_fd < 0 {
        return Err(FdError::InvalidArgument);
    }

    let find_free_fd = |min: i32| -> FdResult<i32> {
        let table = FD_TABLE.read();
        for candidate in min..=MAX_FD {
            if candidate >= RESERVED_FDS && !table.contains_key(&candidate) {
                return Ok(candidate);
            }
        }
        Err(FdError::NoFdsAvailable)
    };

    let new_fd = find_free_fd(min_fd.max(RESERVED_FDS))?;

    if is_stdio(old_fd) {
        let (path, flags) = match old_fd {
            0 => ("/dev/stdin", O_RDONLY),
            1 => ("/dev/stdout", O_WRONLY),
            2 => ("/dev/stderr", O_WRONLY),
            _ => return Err(FdError::InvalidFd),
        };

        let mut table = FD_TABLE.write();
        table.insert(new_fd, OpenFile::new(path.to_string(), flags));
        return Ok(new_fd);
    }

    let entry = {
        let table = FD_TABLE.read();
        table.get(&old_fd).ok_or(FdError::NotOpen)?.clone()
    };

    let mut table = FD_TABLE.write();
    table.insert(new_fd, entry);
    Ok(new_fd)
}

pub fn fd_dup(old_fd: i32) -> FdResult<i32> {
    fd_dup_min(old_fd, RESERVED_FDS)
}

pub fn fd_dup2(old_fd: i32, new_fd: i32) -> FdResult<i32> {
    validate_fd_range(old_fd)?;
    validate_fd_range(new_fd)?;

    if old_fd == new_fd {
        if !fd_is_valid(old_fd) {
            return Err(FdError::NotOpen);
        }
        return Ok(new_fd);
    }

    let _ = fd_close(new_fd);

    if is_stdio(old_fd) {
        let (path, flags) = match old_fd {
            0 => ("/dev/stdin", O_RDONLY),
            1 => ("/dev/stdout", O_WRONLY),
            2 => ("/dev/stderr", O_WRONLY),
            _ => return Err(FdError::InvalidFd),
        };

        if !is_stdio(new_fd) {
            let mut table = FD_TABLE.write();
            table.insert(new_fd, OpenFile::new(path.to_string(), flags));
        }
        return Ok(new_fd);
    }

    let entry = {
        let table = FD_TABLE.read();
        table.get(&old_fd).ok_or(FdError::NotOpen)?.clone()
    };

    if !is_stdio(new_fd) {
        let mut table = FD_TABLE.write();
        table.insert(new_fd, entry);
    }

    Ok(new_fd)
}
