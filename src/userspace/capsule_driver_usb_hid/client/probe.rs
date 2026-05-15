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

use super::limits::{CONFIG_DESCRIPTOR_MAX, HID_BINDING_WIRE_LEN};
use super::seq::next_request_id;
use super::status;
use super::transport::round_trip;
use super::types::{HidBinding, HidKind};
use crate::userspace::capsule_driver_usb_hid::error::UsbHidError;
use crate::userspace::capsule_driver_usb_hid::protocol::{encode_request, OP_PROBE_CONFIG};

pub fn probe_config(raw: &[u8]) -> Result<Vec<HidBinding>, UsbHidError> {
    if raw.is_empty() || raw.len() > CONFIG_DESCRIPTOR_MAX {
        return Err(UsbHidError::InvalidArgument);
    }
    let request_id = next_request_id();
    let frame = encode_request(OP_PROBE_CONFIG, request_id, raw);
    let resp = round_trip(request_id, frame)?;
    if resp.status != 0 {
        return Err(status::map(resp.status));
    }
    decode_bindings(&resp.body)
}

fn decode_bindings(body: &[u8]) -> Result<Vec<HidBinding>, UsbHidError> {
    if body.len() < 4 {
        return Err(UsbHidError::ShortReply);
    }
    let count = u32::from_le_bytes([body[0], body[1], body[2], body[3]]) as usize;
    let expected = 4 + count * HID_BINDING_WIRE_LEN;
    if body.len() < expected {
        return Err(UsbHidError::ShortReply);
    }
    let mut out = Vec::with_capacity(count);
    for i in 0..count {
        let off = 4 + i * HID_BINDING_WIRE_LEN;
        out.push(decode_binding(&body[off..off + HID_BINDING_WIRE_LEN])?);
    }
    Ok(out)
}

fn decode_binding(buf: &[u8]) -> Result<HidBinding, UsbHidError> {
    let kind = match buf[0] {
        1 => HidKind::Keyboard,
        2 => HidKind::Mouse,
        _ => return Err(UsbHidError::ProtocolMismatch),
    };
    Ok(HidBinding {
        kind,
        interface_number: buf[1],
        endpoint_address: buf[2],
        interval: buf[3],
        max_packet_size: u16::from_le_bytes([buf[4], buf[5]]),
    })
}
