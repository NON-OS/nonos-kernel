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

use crate::services::{protocol::ServiceOp, ServiceClient};
use alloc::vec::Vec;

pub struct VfsClient {
    client: ServiceClient,
}

impl VfsClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("vfs").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn read_file(&self, path: &str) -> Result<Vec<u8>, i32> {
        let mut payload = Vec::with_capacity(8 + path.len());
        payload.extend_from_slice(&(path.len() as u32).to_le_bytes());
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(path.as_bytes());
        let resp = self.client.call(ServiceOp::Read, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload)
        } else {
            Err(resp.status)
        }
    }

    pub fn write_file(&self, path: &str, data: &[u8]) -> Result<(), i32> {
        let mut payload = Vec::with_capacity(8 + path.len() + data.len());
        payload.extend_from_slice(&(path.len() as u32).to_le_bytes());
        payload.extend_from_slice(&[0u8; 4]);
        payload.extend_from_slice(path.as_bytes());
        payload.extend_from_slice(data);
        let resp = self.client.call(ServiceOp::Write, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }
}
