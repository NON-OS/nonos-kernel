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

use alloc::vec::Vec;

use super::super::capability::gate_call;
use super::super::error::DriverHdaError;
use super::super::protocol::{
    encode_request, CODEC_ENTRY_BYTES, CODEC_LIST_HEADER_BYTES, MAX_CODECS, OP_CODEC_LIST,
};
use super::seq::next_request_id;
use super::status_map::lift;
use super::transport::round_trip;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HdaCodecInfo {
    pub address: u8,
    pub ok: u8,
    pub vendor_id: u16,
    pub device_id: u16,
}

pub fn codec_list() -> Result<Vec<HdaCodecInfo>, DriverHdaError> {
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_CODEC_LIST, 0, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(lift(resp.status));
    }
    decode_codecs(&resp.body)
}

fn decode_codecs(body: &[u8]) -> Result<Vec<HdaCodecInfo>, DriverHdaError> {
    if body.len() < CODEC_LIST_HEADER_BYTES {
        return Err(DriverHdaError::ProtocolMismatch);
    }
    let count = core::cmp::min(read_u32(body, 0) as usize, MAX_CODECS);
    let need = CODEC_LIST_HEADER_BYTES + count * CODEC_ENTRY_BYTES;
    if body.len() < need {
        return Err(DriverHdaError::ProtocolMismatch);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let o = CODEC_LIST_HEADER_BYTES + i * CODEC_ENTRY_BYTES;
        out.push(HdaCodecInfo {
            address: body[o],
            ok: body[o + 1],
            vendor_id: u16::from_le_bytes([body[o + 2], body[o + 3]]),
            device_id: u16::from_le_bytes([body[o + 4], body[o + 5]]),
        });
    }
    Ok(out)
}

fn read_u32(body: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
}
