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
use alloc::string::String;
use alloc::vec::Vec;

pub struct AppsClient {
    client: ServiceClient,
}

impl AppsClient {
    pub fn connect() -> Result<Self, i32> {
        ServiceClient::connect("apps").map(|c| Self { client: c }).map_err(|_| -1)
    }

    pub fn start(&self, name: &str) -> Result<u64, i32> {
        let resp = self.name_call(1, name)?;
        if resp.payload.len() >= 8 {
            Ok(u64::from_le_bytes(resp.payload[..8].try_into().unwrap()))
        } else {
            Err(-1)
        }
    }

    pub fn stop(&self, name: &str) -> Result<(), i32> {
        self.name_call(2, name).map(|_| ())
    }
    pub fn suspend(&self, name: &str) -> Result<(), i32> {
        self.name_call(3, name).map(|_| ())
    }
    pub fn resume(&self, name: &str) -> Result<(), i32> {
        self.name_call(4, name).map(|_| ())
    }

    pub fn list(&self) -> Result<Vec<String>, i32> {
        let resp = self.client.call(ServiceOp::Ioctl, alloc::vec![5]).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp
                .payload
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .filter_map(|s| core::str::from_utf8(s).ok().map(String::from))
                .collect())
        } else {
            Err(resp.status)
        }
    }

    fn name_call(&self, op: u8, name: &str) -> Result<crate::services::ServiceResponse, i32> {
        let mut p = Vec::with_capacity(1 + name.len());
        p.push(op);
        p.extend_from_slice(name.as_bytes());
        let r = self.client.call(ServiceOp::Ioctl, p).map_err(|_| -1)?;
        if r.status == 0 {
            Ok(r)
        } else {
            Err(r.status)
        }
    }
}
