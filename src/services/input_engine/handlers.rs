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

use crate::services::{ServiceRequest, ServiceResponse};
use alloc::vec::Vec;

const ERR_NODATA: i32 = -11;

pub(super) fn read_keyboard(seq: u32) -> ServiceResponse {
    if let Some(event) = crate::input::keyboard::poll_event() {
        let mut data = Vec::with_capacity(4);
        data.push(event.to_code());
        data.push(1);
        data.push(0);
        data.push(0);
        ServiceResponse::ok(seq, data)
    } else {
        ServiceResponse::err(seq, ERR_NODATA)
    }
}

pub(super) fn read_mouse(seq: u32) -> ServiceResponse {
    let (x, y) = crate::input::mouse_position_unified();
    let left = crate::input::left_button_pressed() as u8;
    let right = crate::input::right_button_pressed() as u8;
    let mut data = Vec::with_capacity(10);
    data.extend_from_slice(&x.to_le_bytes());
    data.extend_from_slice(&y.to_le_bytes());
    data.push(left | (right << 1));
    ServiceResponse::ok(seq, data)
}

pub(super) fn handle_status(req: ServiceRequest) -> ServiceResponse {
    let kb_ready = crate::input::keyboard::has_data() as u8;
    let mouse_ready = crate::input::mouse::is_available() as u8;
    ServiceResponse::ok(req.seq, alloc::vec![kb_ready, mouse_ready])
}
