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

pub struct AudioClient {
    client: ServiceClient,
}

impl AudioClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("audio").map_err(|_| -1)?;
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

    pub fn play(&self, data: &[u8]) -> Result<(), i32> {
        let mut payload = Vec::with_capacity(1 + data.len());
        payload.push(2);
        payload.extend_from_slice(data);
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn pause(&self) -> Result<(), i32> {
        let resp = self.client.call(ServiceOp::Ioctl, alloc::vec![3]).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn resume(&self) -> Result<(), i32> {
        let resp = self.client.call(ServiceOp::Ioctl, alloc::vec![4]).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn stop(&self) -> Result<(), i32> {
        let resp = self.client.call(ServiceOp::Ioctl, alloc::vec![5]).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn is_ready(&self) -> bool {
        self.client
            .call(ServiceOp::Ioctl, alloc::vec![6])
            .map(|r| r.status == 0 && r.payload.first().copied() == Some(1))
            .unwrap_or(false)
    }
}
