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

use super::types::{ServiceOp, ServiceRequest, ServiceResponse, MSG_VERSION};
use alloc::vec::Vec;

impl ServiceRequest {
    pub fn new(seq: u32, op: ServiceOp, payload: Vec<u8>) -> Self {
        Self { seq, op, flags: 0, payload }
    }

    pub fn encode(&self) -> Vec<u8> {
        let mut buf = Vec::with_capacity(12 + self.payload.len());
        buf.push(MSG_VERSION);
        buf.push(0);
        buf.extend_from_slice(&self.seq.to_le_bytes());
        buf.extend_from_slice(&(self.op as u16).to_le_bytes());
        buf.extend_from_slice(&self.flags.to_le_bytes());
        buf.extend_from_slice(&(self.payload.len() as u16).to_le_bytes());
        buf.extend_from_slice(&self.payload);
        buf
    }
}

impl ServiceResponse {
    pub fn ok(seq: u32, payload: Vec<u8>) -> Self {
        Self { seq, status: 0, payload }
    }
    pub fn err(seq: u32, status: i32) -> Self {
        Self { seq, status, payload: Vec::new() }
    }
}
