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

pub struct CryptoClient {
    client: ServiceClient,
}

impl CryptoClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("crypto").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn hash(&self, data: &[u8]) -> Result<[u8; 32], i32> {
        let mut payload = Vec::with_capacity(1 + data.len());
        payload.push(1);
        payload.extend_from_slice(data);
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 && resp.payload.len() >= 32 {
            let mut out = [0u8; 32];
            out.copy_from_slice(&resp.payload[..32]);
            Ok(out)
        } else {
            Err(resp.status)
        }
    }

    pub fn random(&self, len: usize) -> Result<Vec<u8>, i32> {
        let payload = alloc::vec![6, len as u8];
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload)
        } else {
            Err(resp.status)
        }
    }
}
