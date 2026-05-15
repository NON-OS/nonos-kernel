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
use super::super::protocol::{encode_request, CODEC_MASK_PAYLOAD_LEN, OP_CODEC_MASK};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdaCodecMask {
    pub mask: u16,
    pub count: u32,
}

pub fn codec_mask() -> Result<HdaCodecMask, DriverHdaError> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_CODEC_MASK, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    if resp.body.len() < CODEC_MASK_PAYLOAD_LEN {
        return Err(DriverHdaError::ProtocolMismatch);
    }
    Ok(HdaCodecMask { mask: read_u16(&resp.body, 0), count: read_u32(&resp.body, 4) })
}

fn read_u16(body: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([body[off], body[off + 1]])
}

fn read_u32(body: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
}
