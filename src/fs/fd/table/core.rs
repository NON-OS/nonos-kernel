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

use alloc::collections::BTreeMap;
use core::sync::atomic::AtomicI32;
use spin::RwLock;

use crate::fs::fd::error::{FdError, FdResult};
use crate::fs::fd::types::{OpenFile, MAX_FD, RESERVED_FDS};

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
