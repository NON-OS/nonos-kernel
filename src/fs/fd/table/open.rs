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

use core::sync::atomic::Ordering;

use crate::fs::ramfs;
use crate::fs::ramfs::filesystem::mkdir_all;
use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::types::{OpenFile, MAX_FD, RESERVED_FDS, O_CREAT, O_TRUNC, cstr_to_string};

use super::core::{FD_TABLE, NEXT_FD, validate_fd_range, is_stdio};

fn ensure_parent_dirs(path: &str) -> FdResult<()> {
    if let Some(last_slash) = path.rfind('/') {
        if last_slash > 0 {
            let parent = &path[..last_slash];
            mkdir_all(parent)?;
        }
    }
    Ok(())
}

pub fn fd_open(path: &str, flags: i32) -> FdResult<i32> {
    if path.is_empty() {
        return Err(FdError::InvalidPath);
    }

    let normalized = ramfs::normalize_path(path);
    if normalized.is_empty() || normalized == "/" {
        return Err(FdError::InvalidPath);
    }

    let exists = ramfs::exists(&normalized);

    if !exists {
        if (flags & O_CREAT) != 0 {
            ensure_parent_dirs(&normalized)?;
            match ramfs::create_file(&normalized, &[]) {
                Ok(()) => {}
                Err(ramfs::FsError::AlreadyExists) => {}
                Err(e) => return Err(e.into()),
            }
        } else {
            return Err(FdError::NotFound);
        }
    } else if (flags & O_TRUNC) != 0 {
        ramfs::write_file(&normalized, &[])?;
    }

    let mut table = FD_TABLE.write();
    let fd = {
        let mut candidate = NEXT_FD.fetch_add(1, Ordering::SeqCst);
        if candidate > MAX_FD || table.contains_key(&candidate) {
            NEXT_FD.store(RESERVED_FDS, Ordering::SeqCst);
            let mut found_fd = None;
            for i in RESERVED_FDS..=MAX_FD {
                if !table.contains_key(&i) {
                    found_fd = Some(i);
                    NEXT_FD.store(i + 1, Ordering::SeqCst);
                    break;
                }
            }
            match found_fd {
                Some(fd) => fd,
                None => return Err(FdError::NoFdsAvailable),
            }
        } else {
            candidate
        }
    };
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
