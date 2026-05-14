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
use super::super::error::DriverXhciError;
use super::super::protocol::{encode_request, OP_GET_CONFIG_DESCRIPTOR};
use super::seq::next_request_id;
use super::transport::round_trip;

const REPLY_PREFIX: usize = 4;
pub const CONFIG_DESCRIPTOR_MAX_LEN: usize = 512;

pub fn config_descriptor(slot_id: u8, length: u16) -> Result<Vec<u8>, DriverXhciError> {
    if slot_id == 0 || length == 0 || length as usize > CONFIG_DESCRIPTOR_MAX_LEN {
        return Err(DriverXhciError::InvalidArgument);
    }
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let len = length.to_le_bytes();
    let body = [slot_id, 0, len[0], len[1]];
    let frame = encode_request(OP_GET_CONFIG_DESCRIPTOR, 0, request_id, &body);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(DriverXhciError::DeviceFailure);
    }
    decode_reply(&resp.body)
}

fn decode_reply(body: &[u8]) -> Result<Vec<u8>, DriverXhciError> {
    if body.len() < REPLY_PREFIX {
        return Err(DriverXhciError::ShortReply);
    }
    let len = u16::from_le_bytes([body[0], body[1]]) as usize;
    if len > CONFIG_DESCRIPTOR_MAX_LEN || body.len() < REPLY_PREFIX + len {
        return Err(DriverXhciError::ProtocolMismatch);
    }
    Ok(body[REPLY_PREFIX..REPLY_PREFIX + len].to_vec())
}
