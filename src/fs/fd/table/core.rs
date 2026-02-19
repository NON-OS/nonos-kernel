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

use alloc::{collections::BTreeMap, string::String, string::ToString};
use core::sync::atomic::{AtomicI32, Ordering};
use spin::RwLock;

use crate::fs::ramfs;
use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::types::{OpenFile, MAX_FD, RESERVED_FDS, O_CREAT, O_TRUNC, cstr_to_string};

pub(super) static FD_TABLE: RwLock<BTreeMap<i32, OpenFile>> = RwLock::new(BTreeMap::new());
pub(super) static NEXT_FD: AtomicI32 = AtomicI32::new(RESERVED_FDS);

#[inline]
pub fn validate_fd_range(fd: i32) -> FdResult<()> {
    if fd < 0 || fd > MAX_FD {
        Err(FdError::InvalidFd)
    } else {
        Ok(())
    }
}

#[inline]
pub fn is_stdio(fd: i32) -> bool {
    fd >= 0 && fd < RESERVED_FDS
}

pub fn get_entry_read<F, T>(fd: i32, f: F) -> FdResult<T>
where
    F: FnOnce(&OpenFile) -> FdResult<T>,
{
    validate_fd_range(fd)?;
    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }
    let table = FD_TABLE.read();
    let entry = table.get(&fd).ok_or(FdError::NotOpen)?;
    f(entry)
}

pub fn get_entry_write<F, T>(fd: i32, f: F) -> FdResult<T>
where
    F: FnOnce(&mut OpenFile) -> FdResult<T>,
{
    validate_fd_range(fd)?;
    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }
    let mut table = FD_TABLE.write();
    let entry = table.get_mut(&fd).ok_or(FdError::NotOpen)?;
    f(entry)
}

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

pub fn fd_open(path: &str, flags: i32) -> FdResult<i32> {
    let normalized = ramfs::normalize_path(path);
    let exists = ramfs::exists(&normalized);

    if !exists {
        if (flags & O_CREAT) != 0 {
            ramfs::create_file(&normalized, &[])?;
        } else {
            return Err(FdError::NotFound);
        }
    } else if (flags & O_TRUNC) != 0 {
        ramfs::write_file(&normalized, &[])?;
    }

    let fd = loop {
        let candidate = NEXT_FD.fetch_add(1, Ordering::Relaxed);
        if candidate > MAX_FD {
            NEXT_FD.store(RESERVED_FDS, Ordering::Relaxed);
            let table = FD_TABLE.read();
            let mut found_fd = None;
            for i in RESERVED_FDS..=MAX_FD {
                if !table.contains_key(&i) {
                    found_fd = Some(i);
                    break;
                }
            }
            match found_fd {
                Some(fd) => break fd,
                None => return Err(FdError::NoFdsAvailable),
            }
        }
        break candidate;
    };

    let mut table = FD_TABLE.write();
    table.insert(fd, OpenFile::new(normalized, flags));
    Ok(fd)
}

pub fn fd_open_raw(pathname: *const u8, flags: i32) -> FdResult<i32> {
    let path = cstr_to_string(pathname)?;
    fd_open(&path, flags)
}

pub fn fd_close(fd: i32) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Ok(());
    }

    let mut table = FD_TABLE.write();
    if table.remove(&fd).is_some() {
        Ok(())
    } else {
        Err(FdError::NotOpen)
    }
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
