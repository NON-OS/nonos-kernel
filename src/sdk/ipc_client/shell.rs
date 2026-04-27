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

pub struct ShellClient {
    client: ServiceClient,
}

impl ShellClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("shell").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn execute(&self, cmd: &[u8]) -> Result<Vec<u8>, i32> {
        let mut payload = Vec::with_capacity(1 + cmd.len());
        payload.push(1);
        payload.extend_from_slice(cmd);
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload)
        } else {
            Err(resp.status)
        }
    }

    pub fn complete(&self, partial: &[u8]) -> Result<u8, i32> {
        let mut payload = Vec::with_capacity(1 + partial.len());
        payload.push(2);
        payload.extend_from_slice(partial);
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload.first().copied().unwrap_or(0))
        } else {
            Err(resp.status)
        }
    }

    pub fn history(&self) -> Result<Vec<u8>, i32> {
        let resp = self.client.call(ServiceOp::Ioctl, alloc::vec![3]).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload)
        } else {
            Err(resp.status)
        }
    }
}
