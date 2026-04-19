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

use core::mem::size_of;

use crate::fs::ramfs;
use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::types::cstr_to_string;
use crate::fs::fd::table::{validate_fd_range, is_stdio, fd_get_path};

#[repr(C)]
#[derive(Clone, Copy, Default)]
pub struct KernelStat {
    pub mode: u32,
    pub file_type: u32,
    pub size: u64,
    pub atime: u64,
    pub mtime: u64,
    pub ctime: u64,
}

fn write_stat(ptr: *mut u8, st: &KernelStat) -> bool {
    if ptr.is_null() { return false; }
    let bytes: &[u8] = unsafe {
        core::slice::from_raw_parts((st as *const KernelStat) as *const u8, size_of::<KernelStat>())
    };
    crate::usercopy::copy_to_user(ptr as u64, bytes).is_ok()
}

pub fn stat_file_syscall(pathname: *const u8, statbuf: *mut u8) -> bool {
    let path = match cstr_to_string(pathname) {
        Ok(p) => p,
        Err(_) => return false,
    };
    stat_path(&path, statbuf).is_ok()
}

fn stat_path(path: &str, statbuf: *mut u8) -> FdResult<()> {
    let p = ramfs::normalize_path(path);

    if ramfs::NONOS_FILESYSTEM.exists(&p) && ramfs::list_dir(&p).is_ok() {
        let now = crate::time::timestamp_millis() / 1000;
        let st = KernelStat {
            mode: 0o40755,
            file_type: 2,
            size: 4096,
            atime: now,
            mtime: now,
            ctime: now,
        };
        if write_stat(statbuf, &st) {
            return Ok(());
        }
        return Err(FdError::NullPointer);
    }

    match ramfs::NONOS_FILESYSTEM.get_file_info(&p) {
        Ok(info) => {
            let st = KernelStat {
                mode: 0o100000 | info.mode,
                file_type: 1,
                size: info.size as u64,
                atime: info.modified,
                mtime: info.modified,
                ctime: info.created,
            };
            if write_stat(statbuf, &st) {
                Ok(())
            } else {
                Err(FdError::NullPointer)
            }
        }
        Err(_) => Err(FdError::NotFound),
    }
}

pub fn fstat_file_syscall(fd: i32, statbuf: *mut u8) -> bool {
    fd_fstat(fd, statbuf).is_ok()
}

pub fn fd_fstat(fd: i32, statbuf: *mut u8) -> FdResult<()> {
    validate_fd_range(fd)?;

    if statbuf.is_null() {
        return Err(FdError::NullPointer);
    }

    if is_stdio(fd) {
        let st = KernelStat {
            mode: if fd == 0 { 0o444 } else { 0o222 },
            file_type: 3,
            size: 0,
            atime: 0,
            mtime: 0,
            ctime: 0,
        };
        if write_stat(statbuf, &st) {
            return Ok(());
        }
        return Err(FdError::NullPointer);
    }

    let path = fd_get_path(fd)?;
    stat_path(&path, statbuf)
}
