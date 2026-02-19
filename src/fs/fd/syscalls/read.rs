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
use crate::fs::fd::types::{OpenFile, copy_to_user_ptr};
use crate::fs::fd::table::{validate_fd_range, is_stdio, get_entry_read, get_entry_write};

use super::stdio::read_stdin;

pub(crate) fn read_file_impl(entry: &mut OpenFile, buf: *mut u8, count: usize) -> FdResult<usize> {
    if !entry.is_readable() {
        return Err(FdError::NotReadable);
    }

    let data = crate::fs::read_file(&entry.path)?;
    let start = entry.offset.min(data.len());
    let remaining = data.len().saturating_sub(start);
    let to_copy = remaining.min(count);
    if to_copy > 0 {
        // ## SAFETY: Caller guarantees buf is valid
        unsafe {
            copy_to_user_ptr(&data[start..start + to_copy], buf)?;
        }
        entry.offset = entry.offset.saturating_add(to_copy);
    }

    Ok(to_copy)
}

pub(crate) fn read_at_impl(path: &str, buf: *mut u8, count: usize, offset: usize) -> FdResult<usize> {
    let data = crate::fs::read_file(path)?;
    let start = offset.min(data.len());
    let remaining = data.len().saturating_sub(start);
    let to_copy = remaining.min(count);
    if to_copy > 0 {
        // ## SAFETY: Caller guarantees buf is valid
        unsafe {
            copy_to_user_ptr(&data[start..start + to_copy], buf)?;
        }
    }

    Ok(to_copy)
}

pub fn read_file_descriptor(fd: i32, buf: *mut u8, count: usize) -> Option<usize> {
    fd_read(fd, buf, count).ok()
}

pub fn fd_read(fd: i32, buf: *mut u8, count: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;

    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    if count == 0 {
        return Ok(0);
    }

    match fd {
        0 => read_stdin(buf, count),
        1 | 2 => Err(FdError::NotReadable),
        _ => get_entry_write(fd, |entry| read_file_impl(entry, buf, count)),
    }
}

pub fn fd_read_at(fd: i32, buf: *mut u8, count: usize, offset: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;

    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let (path, readable) = get_entry_read(fd, |entry| {
        Ok((entry.path.clone(), entry.is_readable()))
    })?;

    if !readable {
        return Err(FdError::NotReadable);
    }

    read_at_impl(&path, buf, count, offset)
}
