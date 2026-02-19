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

use alloc::vec::Vec;

use crate::fs::ramfs;
use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::types::{OpenFile, copy_from_user_ptr};
use crate::fs::fd::table::{validate_fd_range, is_stdio, get_entry_read, get_entry_write};

use super::stdio::{write_stdout, write_stderr};

pub(crate) fn write_file_impl(entry: &mut OpenFile, buf: *const u8, count: usize) -> FdResult<usize> {
    if !entry.is_writable() {
        return Err(FdError::NotWritable);
    }

    let mut data_to_write = Vec::with_capacity(count);
    data_to_write.resize(count, 0);
    // ## SAFETY: buf validity checked by caller
    unsafe {
        copy_from_user_ptr(buf, &mut data_to_write)?;
    }

    let mut existing = crate::fs::read_file(&entry.path).unwrap_or_default();
    let write_offset = if entry.is_append() {
        existing.len()
    } else {
        entry.offset
    };

    if write_offset > existing.len() {
        existing.resize(write_offset, 0);
    }

    let end_offset = write_offset + count;
    if end_offset > existing.len() {
        existing.resize(end_offset, 0);
    }
    existing[write_offset..end_offset].copy_from_slice(&data_to_write);

    ramfs::write_file(&entry.path, &existing)?;

    entry.offset = end_offset;
    Ok(count)
}

pub fn write_file_descriptor(fd: i32, buf: *const u8, count: usize) -> Option<usize> {
    fd_write(fd, buf, count).ok()
}

pub fn fd_write(fd: i32, buf: *const u8, count: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;

    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    if count == 0 {
        return Ok(0);
    }

    match fd {
        0 => Err(FdError::NotWritable),
        1 => write_stdout(buf, count),
        2 => write_stderr(buf, count),
        _ => get_entry_write(fd, |entry| write_file_impl(entry, buf, count)),
    }
}

pub fn fd_write_at(fd: i32, buf: *const u8, count: usize, offset: usize) -> FdResult<usize> {
    validate_fd_range(fd)?;

    if buf.is_null() {
        return Err(FdError::NullPointer);
    }

    if count == 0 {
        return Ok(0);
    }

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let (path, writable) = get_entry_read(fd, |entry| {
        Ok((entry.path.clone(), entry.is_writable()))
    })?;

    if !writable {
        return Err(FdError::NotWritable);
    }

    let mut data_to_write = Vec::with_capacity(count);
    data_to_write.resize(count, 0);
    // ## SAFETY: buf validity checked above
    unsafe {
        copy_from_user_ptr(buf, &mut data_to_write)?;
    }

    let mut existing = crate::fs::read_file(&path).unwrap_or_default();
    if offset > existing.len() {
        existing.resize(offset, 0);
    }

    let end_offset = offset + count;
    if end_offset > existing.len() {
        existing.resize(end_offset, 0);
    }
    existing[offset..end_offset].copy_from_slice(&data_to_write);

    ramfs::write_file(&path, &existing).map_err(FdError::from)?;
    Ok(count)
}
