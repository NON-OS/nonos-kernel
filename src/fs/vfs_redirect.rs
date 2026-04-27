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

use crate::fs::vfs::{VfsError, VfsResult};
use alloc::vec::Vec;

pub fn read_file(path: &str) -> VfsResult<Vec<u8>> {
    ipc_read_file(path)
}

pub fn write_file(path: &str, data: &[u8]) -> VfsResult<()> {
    ipc_write_file(path, data)
}

fn ipc_read_file(path: &str) -> VfsResult<Vec<u8>> {
    let client =
        crate::services::ServiceClient::connect("vfs").map_err(|_| VfsError::NotInitialized)?;
    let mut payload = Vec::with_capacity(8 + path.len());
    payload.extend_from_slice(&(path.len() as u32).to_le_bytes());
    payload.extend_from_slice(&[0u8; 4]);
    payload.extend_from_slice(path.as_bytes());
    let resp = client
        .call(crate::services::protocol::ServiceOp::Read, payload)
        .map_err(|_| VfsError::IoError("ipc error"))?;
    if resp.status != 0 {
        return Err(VfsError::NotFound);
    }
    Ok(resp.payload)
}

fn ipc_write_file(path: &str, data: &[u8]) -> VfsResult<()> {
    let client =
        crate::services::ServiceClient::connect("vfs").map_err(|_| VfsError::NotInitialized)?;
    let mut payload = Vec::with_capacity(8 + path.len() + data.len());
    payload.extend_from_slice(&(path.len() as u32).to_le_bytes());
    payload.extend_from_slice(&[0u8; 4]);
    payload.extend_from_slice(path.as_bytes());
    payload.extend_from_slice(data);
    let resp = client
        .call(crate::services::protocol::ServiceOp::Write, payload)
        .map_err(|_| VfsError::IoError("ipc error"))?;
    if resp.status != 0 {
        return Err(VfsError::IoError("write failed"));
    }
    Ok(())
}
