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

pub struct AgentsClient {
    client: ServiceClient,
}

impl AgentsClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("agents").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn create(&self, name: &str) -> Result<u32, i32> {
        let mut payload = Vec::with_capacity(1 + name.len());
        payload.push(1);
        payload.extend_from_slice(name.as_bytes());
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 && resp.payload.len() >= 4 {
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&resp.payload[..4]);
            Ok(u32::from_le_bytes(bytes))
        } else {
            Err(resp.status)
        }
    }

    pub fn run(&self, id: u32, prompt: &str) -> Result<(), i32> {
        let mut payload = Vec::with_capacity(5 + prompt.len());
        payload.push(2);
        payload.extend_from_slice(&id.to_le_bytes());
        payload.extend_from_slice(prompt.as_bytes());
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn stop(&self, id: u32) -> Result<(), i32> {
        let mut payload = Vec::with_capacity(5);
        payload.push(3);
        payload.extend_from_slice(&id.to_le_bytes());
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn output(&self, id: u32) -> Result<Vec<u8>, i32> {
        let mut payload = Vec::with_capacity(5);
        payload.push(5);
        payload.extend_from_slice(&id.to_le_bytes());
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload)
        } else {
            Err(resp.status)
        }
    }
}
