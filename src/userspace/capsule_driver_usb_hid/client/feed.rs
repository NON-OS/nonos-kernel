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

use super::limits::{KEY_REPORT_LEN, MOUSE_REPORT_MAX, MOUSE_REPORT_MIN};
use super::seq::next_request_id;
use super::status;
use super::transport::round_trip;
use crate::userspace::capsule_driver_usb_hid::error::UsbHidError;
use crate::userspace::capsule_driver_usb_hid::protocol::{
    encode_request, OP_FEED_KEYBOARD_REPORT, OP_FEED_MOUSE_REPORT,
};

pub fn feed_keyboard_report(report: [u8; KEY_REPORT_LEN]) -> Result<(), UsbHidError> {
    feed(OP_FEED_KEYBOARD_REPORT, &report)
}

pub fn feed_mouse_report(report: &[u8]) -> Result<(), UsbHidError> {
    if report.len() < MOUSE_REPORT_MIN || report.len() > MOUSE_REPORT_MAX {
        return Err(UsbHidError::InvalidArgument);
    }
    feed(OP_FEED_MOUSE_REPORT, report)
}

fn feed(op: u16, body: &[u8]) -> Result<(), UsbHidError> {
    let request_id = next_request_id();
    let frame = encode_request(op, request_id, body);
    let resp = round_trip(request_id, frame)?;
    if resp.status == 0 {
        Ok(())
    } else {
        Err(status::map(resp.status))
    }
}
