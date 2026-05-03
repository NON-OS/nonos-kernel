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
use crate::fs::fd::types::OpenBackend;
use crate::fs::ramfs;
use crate::fs::ramfs_capsule::client as capsule_client;

use super::core::{is_stdio, validate_fd_range, FD_TABLE};

pub fn fd_truncate(fd: i32, length: usize) -> FdResult<()> {
    validate_fd_range(fd)?;

    if is_stdio(fd) {
        return Err(FdError::StdioOperation);
    }

    let snapshot = {
        let table = FD_TABLE.read();
        let entry = table.get(&fd).ok_or(FdError::NotOpen)?;
        if !entry.is_writable() {
            return Err(FdError::NotWritable);
        }
        (entry.backend, entry.path.clone(), entry.remote_handle, entry.capsule_generation)
    };
    let (backend, path, handle, generation) = snapshot;

    match backend {
        OpenBackend::KernelRamfs => {
            let mut data = crate::fs::read_file(&path).unwrap_or_default();
            data.resize(length, 0);
            ramfs::write_file(&path, &data).map_err(FdError::from)
        }
        OpenBackend::CapsuleRamfs => {
            let handle = handle.ok_or(FdError::FsError("capsule fd missing handle"))?;
            let generation = generation.ok_or(FdError::FsError("capsule fd missing generation"))?;
            capsule_client::truncate(handle, generation, length as u64).map_err(FdError::from)
        }
    }
}
