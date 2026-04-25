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

use crate::services::protocol::{ServiceOp, ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

pub(crate) fn extract_pid(client_id: &str) -> u32 {
    client_id.split('.').nth(1).and_then(|s| s.parse().ok()).unwrap_or(0)
}

pub(crate) fn parse_request(data: &[u8]) -> Option<ServiceRequest> {
    if data.len() < 12 {
        return None;
    }
    let seq = u32::from_le_bytes([data[2], data[3], data[4], data[5]]);
    let op_raw = u16::from_le_bytes([data[6], data[7]]);
    let flags = u16::from_le_bytes([data[8], data[9]]);
    let len = u16::from_le_bytes([data[10], data[11]]) as usize;
    let end = 12usize.checked_add(len)?;
    let payload = data.get(12..end).unwrap_or(&[]).to_vec();
    let op = match op_raw {
        0 => ServiceOp::Ping,
        1 => ServiceOp::Open,
        2 => ServiceOp::Close,
        3 => ServiceOp::Read,
        4 => ServiceOp::Write,
        5 => ServiceOp::Ioctl,
        6 => ServiceOp::Query,
        7 => ServiceOp::Subscribe,
        8 => ServiceOp::Unsubscribe,
        _ => return None,
    };
    Some(ServiceRequest { seq, op, flags, payload })
}

pub(crate) fn encode_response(resp: &ServiceResponse) -> Vec<u8> {
    let mut buf = Vec::with_capacity(8 + resp.payload.len());
    buf.extend_from_slice(&resp.seq.to_le_bytes());
    buf.extend_from_slice(&resp.status.to_le_bytes());
    buf.extend_from_slice(&resp.payload);
    buf
}
