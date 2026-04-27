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

pub struct GpuClient {
    client: ServiceClient,
}

impl GpuClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("gpu").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn init(&self) -> Result<(), i32> {
        let resp = self.client.call(ServiceOp::Ioctl, alloc::vec![1]).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn set_mode(&self, width: u16, height: u16) -> Result<(), i32> {
        let mut payload = Vec::with_capacity(5);
        payload.push(2);
        payload.extend_from_slice(&width.to_le_bytes());
        payload.extend_from_slice(&height.to_le_bytes());
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn clear(&self, color: u32) -> Result<(), i32> {
        let mut payload = Vec::with_capacity(5);
        payload.push(3);
        payload.extend_from_slice(&color.to_le_bytes());
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn get_mode(&self) -> Result<(u16, u16), i32> {
        let resp = self.client.call(ServiceOp::Ioctl, alloc::vec![5]).map_err(|_| -1)?;
        if resp.status == 0 && resp.payload.len() >= 4 {
            let w = u16::from_le_bytes([resp.payload[0], resp.payload[1]]);
            let h = u16::from_le_bytes([resp.payload[2], resp.payload[3]]);
            Ok((w, h))
        } else {
            Err(resp.status)
        }
    }
}
