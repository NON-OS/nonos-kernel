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

use super::super::capability::gate_call;
use super::super::error::DriverAhciError;
use super::super::protocol::{encode_request, CONTROLLER_INFO_PAYLOAD_LEN, OP_CONTROLLER_INFO};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AhciControllerInfo {
    pub cap: u32,
    pub ghc: u32,
    pub pi: u32,
    pub version: u32,
    pub cap2: u32,
    pub port_count: u8,
}

pub fn controller_info() -> Result<AhciControllerInfo, DriverAhciError> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_CONTROLLER_INFO, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    decode_controller_info(&resp.body)
}

fn decode_controller_info(body: &[u8]) -> Result<AhciControllerInfo, DriverAhciError> {
    if body.len() < CONTROLLER_INFO_PAYLOAD_LEN {
        return Err(DriverAhciError::ProtocolMismatch);
    }
    Ok(AhciControllerInfo {
        cap: read_u32(body, 0),
        ghc: read_u32(body, 4),
        pi: read_u32(body, 8),
        version: read_u32(body, 12),
        cap2: read_u32(body, 16),
        port_count: body[20],
    })
}

fn read_u32(body: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
}
