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
use crate::fs::fd::types::{SEEK_SET, SEEK_CUR, SEEK_END};
use crate::fs::fd::table::{validate_fd_range, is_stdio, get_entry_write};

pub fn lseek_syscall(fd: i32, offset: i64, whence: i32) -> Result<i64, &'static str> {
    fd_lseek(fd, offset, whence).map_err(|e| e.as_str())
}

pub fn fd_lseek(fd: i32, offset: i64, whence: i32) -> FdResult<i64> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    get_entry_write(fd, |entry| {
        let new_offset = match whence {
            SEEK_SET => {
                if offset < 0 {
                    return Err(FdError::InvalidArgument);
                }
                offset as usize
            }
            SEEK_CUR => {
                if offset < 0 {
                    entry.offset.saturating_sub((-offset) as usize)
                } else {
                    entry.offset.saturating_add(offset as usize)
                }
            }
            SEEK_END => {
                let file_size = ramfs::NONOS_FILESYSTEM
                    .get_file_info(&entry.path)
                    .map(|info| info.size)
                    .unwrap_or(0);

                if offset < 0 {
                    file_size.saturating_sub((-offset) as usize)
                } else {
                    file_size.saturating_add(offset as usize)
                }
            }
            _ => return Err(FdError::InvalidWhence),
        };

        entry.offset = new_offset;
        Ok(new_offset as i64)
    })
}
