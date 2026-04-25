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

pub struct NetClient {
    client: ServiceClient,
}

impl NetClient {
    pub fn connect_service() -> Result<Self, i32> {
        let client = ServiceClient::connect("network").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn tcp_connect(&self, ip: [u8; 4], port: u16) -> Result<u32, i32> {
        let mut payload = Vec::with_capacity(6);
        payload.extend_from_slice(&ip);
        payload.extend_from_slice(&port.to_be_bytes());
        let resp = self.client.call(ServiceOp::Open, payload).map_err(|_| -1)?;
        if resp.status == 0 && resp.payload.len() >= 4 {
            Ok(u32::from_le_bytes([
                resp.payload[0],
                resp.payload[1],
                resp.payload[2],
                resp.payload[3],
            ]))
        } else {
            Err(resp.status)
        }
    }

    pub fn send(&self, conn_id: u32, data: &[u8]) -> Result<usize, i32> {
        let mut payload = Vec::with_capacity(4 + data.len());
        payload.extend_from_slice(&conn_id.to_le_bytes());
        payload.extend_from_slice(data);
        let resp = self.client.call(ServiceOp::Write, payload).map_err(|_| -1)?;
        if resp.status == 0 && resp.payload.len() >= 4 {
            Ok(u32::from_le_bytes([
                resp.payload[0],
                resp.payload[1],
                resp.payload[2],
                resp.payload[3],
            ]) as usize)
        } else {
            Err(resp.status)
        }
    }

    pub fn recv(&self, conn_id: u32, max_len: usize) -> Result<Vec<u8>, i32> {
        let mut payload = Vec::with_capacity(8);
        payload.extend_from_slice(&conn_id.to_le_bytes());
        payload.extend_from_slice(&(max_len as u32).to_le_bytes());
        let resp = self.client.call(ServiceOp::Read, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload)
        } else {
            Err(resp.status)
        }
    }
}
