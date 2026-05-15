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

use super::limits::MOUSE_EVENT_WIRE_LEN;
use super::seq::next_request_id;
use super::status;
use super::transport::round_trip;
use super::types::MouseEvent;
use crate::userspace::capsule_driver_usb_hid::error::UsbHidError;
use crate::userspace::capsule_driver_usb_hid::protocol::{encode_request, OP_POLL_MOUSE};

pub fn poll_mouse() -> Result<Vec<MouseEvent>, UsbHidError> {
    let request_id = next_request_id();
    let frame = encode_request(OP_POLL_MOUSE, request_id, &[]);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(status::map(resp.status));
    }
    decode_mouse(&resp.body)
}

fn decode_mouse(body: &[u8]) -> Result<Vec<MouseEvent>, UsbHidError> {
    if body.len() < 4 {
        return Err(UsbHidError::ShortReply);
    }
    let count = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let expected = 4 + count * MOUSE_EVENT_WIRE_LEN;
    if body.len() < expected {
        return Err(UsbHidError::ShortReply);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * MOUSE_EVENT_WIRE_LEN;
        out.push(MouseEvent {
            dx: i16::from_le_bytes([body[off], body[off + 1]]),
            dy: i16::from_le_bytes([body[off + 2], body[off + 3]]),
            dz: body[off + 4] as i8,
            buttons: body[off + 5],
            flags: body[off + 6],
        });
    }
    Ok(out)
}
