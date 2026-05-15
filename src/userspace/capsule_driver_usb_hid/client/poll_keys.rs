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

use alloc::vec::Vec;

use super::limits::KEY_EVENT_WIRE_LEN;
use super::seq::next_request_id;
use super::status;
use super::transport::round_trip;
use super::types::KeyEvent;
use crate::userspace::capsule_driver_usb_hid::error::UsbHidError;
use crate::userspace::capsule_driver_usb_hid::protocol::{encode_request, OP_POLL_KEYS};

pub fn poll_keys() -> Result<Vec<KeyEvent>, UsbHidError> {
    let request_id = next_request_id();
    let frame = encode_request(OP_POLL_KEYS, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(status::map(resp.status));
    }
    decode_keys(&resp.body)
}

fn decode_keys(body: &[u8]) -> Result<Vec<KeyEvent>, UsbHidError> {
    if body.len() < 4 {
        return Err(UsbHidError::ShortReply);
    }
    let count = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let expected = 4 + count * KEY_EVENT_WIRE_LEN;
    if body.len() < expected {
        return Err(UsbHidError::ShortReply);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * KEY_EVENT_WIRE_LEN;
        out.push(KeyEvent {
            scancode: body[off],
            ascii: body[off + 1],
            modifiers: body[off + 2],
            pressed: body[off + 3] != 0,
        });
    }
    Ok(out)
}
