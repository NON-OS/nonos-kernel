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

pub struct InputClient {
    client: ServiceClient,
}

impl InputClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("input").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn read_keyboard(&self) -> Result<Option<u8>, i32> {
        let payload = alloc::vec![1u8];
        let resp = self.client.call(ServiceOp::Read, payload).map_err(|_| -1)?;
        if resp.status == 0 && !resp.payload.is_empty() {
            Ok(Some(resp.payload[0]))
        } else if resp.status == -11 {
            Ok(None)
        } else {
            Err(resp.status)
        }
    }

    pub fn read_mouse(&self) -> Result<(i32, i32, u8), i32> {
        let payload = alloc::vec![2u8];
        let resp = self.client.call(ServiceOp::Read, payload).map_err(|_| -1)?;
        if resp.status == 0 && resp.payload.len() >= 9 {
            let x = i32::from_le_bytes([
                resp.payload[0],
                resp.payload[1],
                resp.payload[2],
                resp.payload[3],
            ]);
            let y = i32::from_le_bytes([
                resp.payload[4],
                resp.payload[5],
                resp.payload[6],
                resp.payload[7],
            ]);
            let btns = resp.payload[8];
            Ok((x, y, btns))
        } else {
            Err(resp.status)
        }
    }

    pub fn get_status(&self) -> Result<(bool, bool), i32> {
        let resp = self.client.call(ServiceOp::Query, Vec::new()).map_err(|_| -1)?;
        if resp.status == 0 && resp.payload.len() >= 2 {
            Ok((resp.payload[0] != 0, resp.payload[1] != 0))
        } else {
            Err(resp.status)
        }
    }
}
