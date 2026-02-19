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
use crate::fs::fd::types::MAX_FD;

use super::core::{FD_TABLE, validate_fd_range};

pub fn fd_has_data(fd: i32) -> bool {
    if fd < 0 || fd > MAX_FD {
        return false;
    }

    match fd {
        0 => crate::drivers::keyboard_buffer::has_data(),
        1 | 2 => false,
        _ => {
            let table = FD_TABLE.read();
            if let Some(entry) = table.get(&fd) {
                if let Ok(data) = crate::fs::read_file(&entry.path) {
                    entry.offset < data.len()
                } else {
                    false
                }
            } else {
                false
            }
        }
    }
}

pub fn fd_can_write(fd: i32) -> bool {
    if fd < 0 || fd > MAX_FD {
        return false;
    }

    match fd {
        0 => false,
        1 | 2 => true,
        _ => {
            let table = FD_TABLE.read();
            table.get(&fd).map(|e| e.is_writable()).unwrap_or(false)
        }
    }
}

pub fn fd_is_closed_remote(fd: i32) -> bool {
    if fd < 0 || fd > MAX_FD {
        return true;
    }

    match fd {
        0 | 1 | 2 => false,
        _ => {
            let table = FD_TABLE.read();
            !table.contains_key(&fd)
        }
    }
}

pub fn fd_bytes_available(fd: i32) -> FdResult<usize> {
    validate_fd_range(fd)?;

    match fd {
        0 => Ok(crate::drivers::keyboard_buffer::available_count()),
        1 | 2 => Err(FdError::NotReadable),
        _ => {
            let table = FD_TABLE.read();
            let entry = table.get(&fd).ok_or(FdError::NotOpen)?;

            if !entry.is_readable() {
                return Err(FdError::NotReadable);
            }

            let data = crate::fs::read_file(&entry.path)?;
            Ok(data.len().saturating_sub(entry.offset))
        }
    }
}

pub fn fd_is_writable(fd: i32) -> bool {
    fd_can_write(fd)
}
