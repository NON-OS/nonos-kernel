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

pub struct ZkClient {
    client: ServiceClient,
}

impl ZkClient {
    pub fn connect() -> Result<Self, i32> {
        let client = ServiceClient::connect("zk").map_err(|_| -1)?;
        Ok(Self { client })
    }

    pub fn generate_proof(&self, witness: &[u8]) -> Result<Vec<u8>, i32> {
        let mut payload = Vec::with_capacity(1 + witness.len());
        payload.push(1);
        payload.extend_from_slice(witness);
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload)
        } else {
            Err(resp.status)
        }
    }

    pub fn verify_proof(
        &self,
        commitment: &[u8; 32],
        nonce: &[u8; 32],
        public_input: &[u8],
    ) -> Result<bool, i32> {
        let mut payload = Vec::with_capacity(65 + public_input.len());
        payload.push(2);
        payload.extend_from_slice(commitment);
        payload.extend_from_slice(nonce);
        payload.extend_from_slice(public_input);
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 && !resp.payload.is_empty() {
            Ok(resp.payload[0] != 0)
        } else {
            Err(resp.status)
        }
    }

    pub fn create_attestation(&self, claim: &[u8]) -> Result<Vec<u8>, i32> {
        let mut payload = Vec::with_capacity(1 + claim.len());
        payload.push(3);
        payload.extend_from_slice(claim);
        let resp = self.client.call(ServiceOp::Ioctl, payload).map_err(|_| -1)?;
        if resp.status == 0 {
            Ok(resp.payload)
        } else {
            Err(resp.status)
        }
    }
}
