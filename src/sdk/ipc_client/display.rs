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

pub struct DisplayClient {
    client: ServiceClient,
}

impl DisplayClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("display").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn get_info(&self) -> Result<(u32, u32, u32, u32), i32> {
        let resp = self.client.call(ServiceOp::Query, Vec::new()).map_err(|_| -1)?;
        if resp.status == 0 && resp.payload.len() >= 16 {
            let w = u32::from_le_bytes([
                resp.payload[0],
                resp.payload[1],
                resp.payload[2],
                resp.payload[3],
            ]);
            let h = u32::from_le_bytes([
                resp.payload[4],
                resp.payload[5],
                resp.payload[6],
                resp.payload[7],
            ]);
            let s = u32::from_le_bytes([
                resp.payload[8],
                resp.payload[9],
                resp.payload[10],
                resp.payload[11],
            ]);
            let b = u32::from_le_bytes([
                resp.payload[12],
                resp.payload[13],
                resp.payload[14],
                resp.payload[15],
            ]);
            Ok((w, h, s, b))
        } else {
            Err(resp.status)
        }
    }

    pub fn draw_pixel(&self, x: u32, y: u32, color: u32) -> Result<(), i32> {
        let mut payload = Vec::with_capacity(13);
        payload.push(1);
        payload.extend_from_slice(&x.to_le_bytes());
        payload.extend_from_slice(&y.to_le_bytes());
        payload.extend_from_slice(&color.to_le_bytes());
        let resp = self.client.call(ServiceOp::Write, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }

    pub fn fill_rect(&self, x: u32, y: u32, w: u32, h: u32, color: u32) -> Result<(), i32> {
        let mut payload = Vec::with_capacity(21);
        payload.push(2);
        payload.extend_from_slice(&x.to_le_bytes());
        payload.extend_from_slice(&y.to_le_bytes());
        payload.extend_from_slice(&w.to_le_bytes());
        payload.extend_from_slice(&h.to_le_bytes());
        payload.extend_from_slice(&color.to_le_bytes());
        let resp = self.client.call(ServiceOp::Write, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(())
        } else {
            Err(resp.status)
        }
    }
}
