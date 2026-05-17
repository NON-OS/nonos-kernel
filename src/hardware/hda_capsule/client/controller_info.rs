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
use super::super::error::DriverHdaError;
use super::super::protocol::{encode_request, CONTROLLER_INFO_PAYLOAD_LEN, OP_CONTROLLER_INFO};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdaControllerInfo {
    pub gcap: u16,
    pub vmin: u8,
    pub vmaj: u8,
    pub outpay: u16,
    pub inpay: u16,
    pub gctl: u32,
    pub statests: u16,
    pub gsts: u16,
    pub intctl: u32,
    pub intsts: u32,
    pub input_streams: u8,
    pub output_streams: u8,
    pub bidi_streams: u8,
    pub addr64: u8,
}

pub fn controller_info() -> Result<HdaControllerInfo, DriverHdaError> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_CONTROLLER_INFO, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    decode(&resp.body)
}

fn decode(body: &[u8]) -> Result<HdaControllerInfo, DriverHdaError> {
    if body.len() < CONTROLLER_INFO_PAYLOAD_LEN {
        return Err(DriverHdaError::ProtocolMismatch);
    }
    Ok(HdaControllerInfo {
        gcap: read_u16(body, 0),
        vmin: body[2],
        vmaj: body[3],
        outpay: read_u16(body, 4),
        inpay: read_u16(body, 6),
        gctl: read_u32(body, 8),
        statests: read_u16(body, 12),
        gsts: read_u16(body, 14),
        intctl: read_u32(body, 16),
        intsts: read_u32(body, 20),
        input_streams: body[24],
        output_streams: body[25],
        bidi_streams: body[26],
        addr64: body[27],
    })
}

fn read_u16(body: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([body[off], body[off + 1]])
}

fn read_u32(body: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
}
