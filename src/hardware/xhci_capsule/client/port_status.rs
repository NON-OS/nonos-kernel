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

//! Decode the bounded PORT_STATUS payload. The capsule clears
//! PORTSC change bits before replying, so subsequent calls
//! reflect only new transitions.

use alloc::vec::Vec;

use super::super::capability::gate_call;
use super::super::error::DriverXhciError;
use super::super::protocol::{encode_request, MAX_PORTS_REPORTED, OP_PORT_STATUS};
use super::seq::next_request_id;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy)]
pub struct PortSnapshot {
    pub port_id: u8,
    pub portsc_raw: u32,
}

const HEADER_BYTES: usize = 4;
const ENTRY_BYTES: usize = 8;

pub fn port_status() -> Result<Vec<PortSnapshot>, DriverXhciError> {
    let _caller = gate_call()?;
    let body: [u8; 0] = [];
    let request_id = next_request_id();
    let frame = encode_request(OP_PORT_STATUS, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(DriverXhciError::DeviceFailure);
    }
    if resp.body.len() < HEADER_BYTES {
        return Err(DriverXhciError::ShortReply);
    }
    let count = resp.body[0] as usize;
    if count > MAX_PORTS_REPORTED {
        return Err(DriverXhciError::ProtocolMismatch);
    }
    let needed = HEADER_BYTES + count * ENTRY_BYTES;
    if resp.body.len() < needed {
        return Err(DriverXhciError::ShortReply);
    }
    let mut out = Vec::with_capacity(count);
    let mut o = HEADER_BYTES;
    for _ in 0..count {
        let port_id = resp.body[o];
        let portsc =
            u32::from_le_bytes([resp.body[o + 4], resp.body[o + 5], resp.body[o + 6], resp.body[o + 7]]);
        out.push(PortSnapshot { port_id, portsc_raw: portsc });
        o += ENTRY_BYTES;
    }
    Ok(out)
}
