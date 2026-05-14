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
use super::super::error::DriverXhciError;
use super::super::protocol::{encode_request, OP_GET_DEVICE_DESCRIPTOR};
use super::seq::next_request_id;
use super::transport::round_trip;

pub const DEVICE_DESCRIPTOR_LEN: usize = 18;

pub fn device_descriptor(slot_id: u8) -> Result<[u8; DEVICE_DESCRIPTOR_LEN], DriverXhciError> {
    if slot_id == 0 {
        return Err(DriverXhciError::InvalidArgument);
    }
    let _caller = gate_call()?;
    let request_id = next_request_id();
    let frame = encode_request(OP_GET_DEVICE_DESCRIPTOR, 0, request_id, &[slot_id]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(DriverXhciError::DeviceFailure);
    }
    if resp.body.len() < DEVICE_DESCRIPTOR_LEN {
        return Err(DriverXhciError::ShortReply);
    }
    let mut out = [0u8; DEVICE_DESCRIPTOR_LEN];
    out.copy_from_slice(&resp.body[..DEVICE_DESCRIPTOR_LEN]);
    Ok(out)
}
