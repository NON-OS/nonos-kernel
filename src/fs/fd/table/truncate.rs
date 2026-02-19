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

use super::core::{FD_TABLE, validate_fd_range, is_stdio};

pub fn fd_truncate(fd: i32, length: usize) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let path = {
        let table = FD_TABLE.read();
        let entry = table.get(&fd).ok_or(FdError::NotOpen)?;

        if !entry.is_writable() {
            return Err(FdError::NotWritable);
        }

        entry.path.clone()
    };

    let mut data = crate::fs::read_file(&path).unwrap_or_default();
    data.resize(length, 0);

    ramfs::write_file(&path, &data).map_err(FdError::from)
}
