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

use crate::fs::ramfs;
use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::table::{validate_fd_range, is_stdio, get_entry_read};

pub fn fd_sync(fd: i32) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Ok(());
    }

    get_entry_read(fd, |entry| {
        if !ramfs::NONOS_FILESYSTEM.exists(&entry.path) {
            return Err(FdError::NotFound);
        }
        Ok(())
    })?;

    Ok(())
}

pub fn fd_allocate(fd: i32, offset: usize, len: usize) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let path = get_entry_read(fd, |entry| {
        if !entry.is_writable() {
            return Err(FdError::NotWritable);
        }
        Ok(entry.path.clone())
    })?;

    let mut data = crate::fs::read_file(&path).unwrap_or_default();
    let required_size = offset.saturating_add(len);
    if required_size > data.len() {
        data.resize(required_size, 0);
        ramfs::write_file(&path, &data).map_err(FdError::from)?;
    }

    Ok(())
}

pub fn fd_chmod(fd: i32, mode: u32) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let path = get_entry_read(fd, |entry| Ok(entry.path.clone()))?;
    if !ramfs::NONOS_FILESYSTEM.exists(&path) {
        return Err(FdError::NotFound);
    }

    let _ = mode;
    Ok(())
}

pub fn fd_chown(fd: i32, owner: u32, group: u32) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let path = get_entry_read(fd, |entry| Ok(entry.path.clone()))?;
    if !ramfs::NONOS_FILESYSTEM.exists(&path) {
        return Err(FdError::NotFound);
    }

    let _ = owner;
    let _ = group;
    Ok(())
}

pub fn sync_all() -> Result<(), &'static str> {
    Ok(())
}
