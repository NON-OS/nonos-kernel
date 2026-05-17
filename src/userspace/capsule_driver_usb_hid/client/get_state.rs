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

use super::limits::STATE_REPLY_LEN;
use super::seq::next_request_id;
use super::status;
use super::transport::round_trip;
use super::types::UsbHidState;
use crate::userspace::capsule_driver_usb_hid::error::UsbHidError;
use crate::userspace::capsule_driver_usb_hid::protocol::{encode_request, OP_GET_STATE};

pub fn get_state() -> Result<UsbHidState, UsbHidError> {
    let request_id = next_request_id();
    let frame = encode_request(OP_GET_STATE, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(status::map(resp.status));
    }
    decode_state(&resp.body)
}

fn decode_state(body: &[u8]) -> Result<UsbHidState, UsbHidError> {
    if body.len() < STATE_REPLY_LEN {
        return Err(UsbHidError::ShortReply);
    }
    Ok(UsbHidState {
        configs_probed: read_u64(body, 0),
        key_reports: read_u64(body, 8),
        mouse_reports: read_u64(body, 16),
        pending_keys: read_u32(body, 24),
        pending_mouse: read_u32(body, 28),
    })
}

fn read_u64(body: &[u8], off: usize) -> u64 {
    u64::from_le_bytes([
        body[off],
        body[off + 1],
        body[off + 2],
        body[off + 3],
        body[off + 4],
        body[off + 5],
        body[off + 6],
        body[off + 7],
    ])
}

fn read_u32(body: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([body[off], body[off + 1], body[off + 2], body[off + 3]])
}
